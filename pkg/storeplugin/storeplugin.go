// Package storeplugin is the SDK for zeroauthy storage plugins: separate
// executables that store zeroauthy's data and talk to it over gRPC
// (hashicorp/go-plugin). A plugin's main calls Serve with its store.Store;
// zeroauthy starts it from a plugin:///path DSN. Run pkg/storetest against
// Open(path) to check a plugin before shipping it.
//
// Notes for plugin authors:
//
//   - Implement Protection atomically in the shared backing store, including
//     transaction views. New hosts fail closed with a plugin-too-old diagnostic
//     if any protection RPC is missing; there is no local counter fallback.
//   - Keep main to a single call, storeplugin.Serve(yourStore).
//   - Stdout carries the go-plugin handshake, so write logs to stderr only.
//     Lines on stderr that start with "[ERROR] " reach the host's log.
//   - Running the binary by hand just prints go-plugin's message that it is
//     a plugin and exits.
//   - If a wrapper script starts the real binary, use exec so no extra
//     process sits in between, and never fork children that inherit stdio:
//     stopping the plugin waits for every holder of its pipes.
//   - Log levels: the host shows plugin stderr lines that start with
//     "[WARN] " or "[ERROR] "; unprefixed lines are logged at debug level,
//     which the host's default level hides.
//   - Configuration comes through the plugin's arguments (the arg values of
//     the plugin:// DSN). The host removes every ZEROAUTHY_* variable from
//     the environment it hands the plugin, so zeroauthy's own secrets (the
//     master key, the storage DSN) never reach it; other variables such as
//     PATH, HOME and PG* are kept.
//   - Host death: the plugin polls its parent process and exits within
//     about a second after the host dies (go-plugin has no such check), so
//     a crashed host does not leave plugins behind. Open transactions are
//     abandoned, as below.
//   - Do not count on cleanup at exit. The process may be killed, and open
//     transactions are simply abandoned; a database rolls them back when
//     the connection drops.
package storeplugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store/grpcstore"
	"github.com/zeroauthy/zeroauthy/pkg/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// Handshake must match between zeroauthy and the plugin.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "ZEROAUTHY_STORE_PLUGIN",
	MagicCookieValue: "5b0f7c1e-store-v1",
}

const pluginName = "store"

// StartTimeout bounds how long Open waits for the plugin's handshake.
const StartTimeout = 10 * time.Second

type grpcPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl store.Store
}

func registerStore(s *grpc.Server, gs *grpcstore.Server) {
	storev1.RegisterStoreServiceServer(s, gs)
}

func (p *grpcPlugin) GRPCServer(_ *plugin.GRPCBroker, s *grpc.Server) error {
	registerStore(s, grpcstore.NewServer(p.impl))
	return nil
}

func (p *grpcPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, conn *grpc.ClientConn) (any, error) {
	return conn, nil
}

// recoverPanics turns a panic in one request handler into an Internal
// status so the plugin process keeps serving.
func recoverPanics(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] storage plugin: panic in %s: %v\n", info.FullMethod, r)
			resp, err = nil, status.Error(codes.Internal, "plugin handler panicked")
		}
	}()
	return h(ctx, req)
}

func serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{grpc.ChainUnaryInterceptor(recoverPanics)}
}

// parentPollInterval is how often a plugin checks that its host still lives.
const parentPollInterval = time.Second

// exitWithParent exits the process once the host that started it is gone:
// the plugin is then re-parented, so its parent pid changes.
func exitWithParent() {
	ppid := os.Getppid()
	for range time.Tick(parentPollInterval) {
		if os.Getppid() != ppid {
			fmt.Fprintln(os.Stderr, "[WARN] storage plugin: host process is gone; exiting")
			os.Exit(1)
		}
	}
}

// Serve runs s as a zeroauthy storage plugin. It does not return. The
// process exits on its own when the host dies.
func Serve(s store.Store) {
	if os.Getenv(Handshake.MagicCookieKey) == Handshake.MagicCookieValue {
		go exitWithParent()
	}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         plugin.PluginSet{pluginName: &grpcPlugin{impl: s}},
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			return plugin.DefaultGRPCServer(append(opts, serverOptions()...))
		},
	})
}

// Open starts the plugin at path (absolute) with args and returns a
// store.Store backed by it. Closing the store stops the plugin.
// Errors never include args, which may carry secrets.
func Open(ctx context.Context, path string, args ...string) (store.Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("storage plugin: the binary path must be absolute")
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		return nil, errors.New("storage plugin: the binary does not exist or is not executable")
	}
	// client.Kill blocks while a start is in flight, so cancelling ctx
	// kills the process through this context instead; it lives as long as
	// the plugin does and is cancelled when the store is closed.
	procCtx, stop := context.WithCancel(context.Background())
	cmd := exec.CommandContext(procCtx, path, args...)
	// The plugin gets its configuration from args; zeroauthy's own
	// variables (master key, storage DSN) stay with the host.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "ZEROAUTHY_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          plugin.PluginSet{pluginName: &grpcPlugin{}},
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		SkipHostEnv:      true,
		StartTimeout:     StartTimeout,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "storage-plugin", Output: os.Stderr, Level: hclog.Warn}),
	})
	type started struct {
		rpc plugin.ClientProtocol
		err error
	}
	startCh := make(chan started, 1)
	go func() {
		rpc, err := client.Client()
		startCh <- started{rpc, err}
	}()
	var rpc plugin.ClientProtocol
	select {
	case r := <-startCh:
		if r.err != nil {
			stop()
			client.Kill()
			return nil, errors.New("storage plugin: start failed (handshake): " + r.err.Error())
		}
		rpc = r.rpc
	case <-ctx.Done():
		stop()
		<-startCh
		client.Kill()
		return nil, ctx.Err()
	}
	raw, err := rpc.Dispense(pluginName)
	if err != nil {
		stop()
		client.Kill()
		return nil, errors.New("storage plugin: dispense failed: " + err.Error())
	}
	conn := raw.(*grpc.ClientConn)
	st := grpcstore.NewClient(conn, func() error { client.Kill(); stop(); return nil })
	if err := st.Ping(ctx); err != nil {
		client.Kill()
		stop()
		return nil, err
	}
	return &opened{Store: st, client: client}, nil
}

type opened struct {
	store.Store
	client *plugin.Client
}

// KillForTest stops the plugin process behind a store returned by Open,
// without closing the store. It exists for crash tests.
func KillForTest(s store.Store) {
	if o, ok := s.(*opened); ok {
		o.client.Kill()
	}
}
