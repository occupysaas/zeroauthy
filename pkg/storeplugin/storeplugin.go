// Package storeplugin is the SDK for zeroauthy storage plugins: separate
// executables that store zeroauthy's data and talk to it over gRPC
// (hashicorp/go-plugin). A plugin's main calls Serve with its store.Store;
// zeroauthy starts it from a plugin:///path DSN. Run pkg/storetest against
// Open(path) to check a plugin before shipping it.
package storeplugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
			fmt.Fprintf(os.Stderr, "storage plugin: panic in %s: %v\n", info.FullMethod, r)
			resp, err = nil, status.Error(codes.Internal, "plugin handler panicked")
		}
	}()
	return h(ctx, req)
}

func serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{grpc.ChainUnaryInterceptor(recoverPanics)}
}

// Serve runs s as a zeroauthy storage plugin. It does not return.
func Serve(s store.Store) {
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
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  Handshake,
		Plugins:          plugin.PluginSet{pluginName: &grpcPlugin{}},
		Cmd:              exec.Command(path, args...),
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		StartTimeout:     StartTimeout,
		Logger:           hclog.New(&hclog.LoggerOptions{Name: "storage-plugin", Output: os.Stderr, Level: hclog.Warn}),
	})
	rpc, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, errors.New("storage plugin: start failed (handshake): " + err.Error())
	}
	raw, err := rpc.Dispense(pluginName)
	if err != nil {
		client.Kill()
		return nil, errors.New("storage plugin: dispense failed: " + err.Error())
	}
	conn := raw.(*grpc.ClientConn)
	st := grpcstore.NewClient(conn, func() error { client.Kill(); return nil })
	if err := st.Ping(ctx); err != nil {
		client.Kill()
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
