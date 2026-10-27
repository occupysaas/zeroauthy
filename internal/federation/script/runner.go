// Package script runs custom OAuth2 fetchUserProfile scripts in a dedicated,
// restricted Node.js runner (spec §6). It is separate from internal/customdb:
// it never enables network access, starts one short-lived process per
// execution (a fresh context with no shared token-bearing globals), and
// reaches the network only through the host broker.
package script

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed runner.mjs
var runnerJS []byte

// Errors. Messages are operator diagnostics: they never contain script
// output, provider responses or tokens.
var (
	// ErrUnavailable: Node is missing, too old, or cannot prove network
	// denial. Only custom OAuth2 login is affected.
	ErrUnavailable = errors.New("script: profile script runtime unavailable")
	ErrScript      = errors.New("script: profile script failed")
	ErrTimeout     = errors.New("script: profile script timed out")
	ErrProtocol    = errors.New("script: profile script runner protocol error")
)

// Request is one execution.
type Request struct {
	TenantID     string
	ConnectionID string
	Source       string
	AccessToken  string
	// Context is the bounded JSON context (allowlisted token-response
	// scalars).
	Context map[string]any
}

// Executor runs profile scripts; the result is the profile passed to the
// callback.
type Executor interface {
	Execute(ctx context.Context, req Request) (json.RawMessage, error)
	Close() error
}

// Config sets the runner limits; zero fields take the spec defaults.
type Config struct {
	Node      string        // default "node"
	Deadline  time.Duration // default 5 s
	HeapMiB   int           // default 64
	PerTenant int           // default 8
	Global    int           // default 64
}

const (
	maxSourceBytes = 65536
	maxOutputLine  = 96 << 10 // a 64 KiB profile plus JSON framing
	maxContext     = 65536
	minNodeMajor   = 25
)

// Runner is the Node-backed Executor.
type Runner struct {
	cfg    Config
	broker *Broker
	dir    string

	global  chan struct{}
	mu      sync.Mutex
	tenants map[string]chan struct{}
	closed  bool

	probeOnce sync.Once
	probeErr  error

	onStart, onEnd func() // tests
}

var _ Executor = (*Runner)(nil)

// NewRunner writes runner.mjs to a private directory. Node starts per
// execution, after Probe has passed once.
func NewRunner(cfg Config, broker *Broker) (*Runner, error) {
	if cfg.Node == "" {
		cfg.Node = "node"
	}
	if cfg.Deadline <= 0 {
		cfg.Deadline = 5 * time.Second
	}
	if cfg.HeapMiB <= 0 {
		cfg.HeapMiB = 64
	}
	if cfg.PerTenant <= 0 {
		cfg.PerTenant = 8
	}
	if cfg.Global <= 0 {
		cfg.Global = 64
	}
	dir, err := os.MkdirTemp("", "zeroauthy-profile-")
	if err != nil {
		return nil, fmt.Errorf("script: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err == nil {
		err = os.WriteFile(filepath.Join(dir, "runner.mjs"), runnerJS, 0o600)
	}
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("script: %w", err)
	}
	return &Runner{cfg: cfg, broker: broker, dir: dir, global: make(chan struct{}, cfg.Global), tenants: map[string]chan struct{}{}}, nil
}

// Close removes the runner directory; running executions finish or die by
// their own deadlines.
func (r *Runner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return os.RemoveAll(r.dir)
}

func checkNodeVersion(v string) error {
	major, err := strconv.Atoi(strings.SplitN(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".", 2)[0])
	if err != nil {
		return fmt.Errorf("%w: unrecognised node version", ErrUnavailable)
	}
	if major < minNodeMajor {
		return fmt.Errorf("%w: node %s is too old; profile scripts need Node %d or later", ErrUnavailable, strings.TrimSpace(v), minNodeMajor)
	}
	return nil
}

// probeJS tries a socket and fetch under the runner's own flags; both must
// be denied by the permission model.
const probeJS = `const net = require('node:net');
const code = (e) => (e && (e.code || (e.cause && e.cause.code))) || 'error';
const socket = new Promise((resolve) => {
  try {
    const s = net.connect(65530, '127.0.0.1');
    s.on('error', (e) => resolve(code(e)));
    s.on('connect', () => { s.destroy(); resolve('allowed'); });
  } catch (e) { resolve(code(e)); }
});
const fetched = fetch('http://127.0.0.1:65530/').then(() => 'allowed', code);
Promise.all([socket, fetched]).then(([s, f]) => process.stdout.write(JSON.stringify({socket: s, fetch: f})));`

func (r *Runner) probe() error {
	cmd := exec.Command(r.cfg.Node, "--version")
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: running node --version failed", ErrUnavailable)
	}
	if err := checkNodeVersion(string(out)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := exec.CommandContext(ctx, r.cfg.Node, "--permission", "-e", probeJS)
	p.Env, p.Dir = []string{}, r.dir
	out, err = p.Output()
	var got struct{ Socket, Fetch string }
	if err != nil || json.Unmarshal(out, &got) != nil || got.Socket != "ERR_ACCESS_DENIED" || got.Fetch != "ERR_ACCESS_DENIED" {
		return fmt.Errorf("%w: the permission model does not deny network access (socket=%q fetch=%q)", ErrUnavailable, got.Socket, got.Fetch)
	}
	return nil
}

// Probe checks once that Node can run profile scripts with network access
// denied, and caches the answer.
func (r *Runner) Probe() error {
	r.probeOnce.Do(func() { r.probeErr = r.probe() })
	return r.probeErr
}

func (r *Runner) acquire(ctx context.Context, tenantID string) (func(), error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: runner closed", ErrUnavailable)
	}
	t, ok := r.tenants[tenantID]
	if !ok {
		t = make(chan struct{}, r.cfg.PerTenant)
		r.tenants[tenantID] = t
	}
	r.mu.Unlock()
	select {
	case t <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case r.global <- struct{}{}:
	case <-ctx.Done():
		<-t
		return nil, ctx.Err()
	}
	return func() { <-r.global; <-t }, nil
}

type wireMessage struct {
	Exec        string          `json:"exec"`
	Type        string          `json:"type,omitempty"`
	ID          int64           `json:"id,omitempty"`
	Options     *GetOptions     `json:"options,omitempty"`
	Error       string          `json:"error,omitempty"`
	Profile     json.RawMessage `json:"profile,omitempty"`
	Response    *GetResult      `json:"response,omitempty"`
	Body        *string         `json:"body,omitempty"`
	Source      string          `json:"source,omitempty"`
	AccessToken string          `json:"accessToken,omitempty"`
	Context     map[string]any  `json:"context,omitempty"`
}

// Execute runs req in a fresh Node process under the deadline.
func (r *Runner) Execute(ctx context.Context, req Request) (json.RawMessage, error) {
	if err := r.Probe(); err != nil {
		return nil, err
	}
	if req.Source == "" || len(req.Source) > maxSourceBytes {
		return nil, fmt.Errorf("%w: script source missing or too large", ErrScript)
	}
	if b, err := json.Marshal(req.Context); err != nil || len(b) > maxContext {
		return nil, fmt.Errorf("%w: context too large", ErrScript)
	}
	release, err := r.acquire(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	if r.onStart != nil {
		r.onStart()
		defer r.onEnd()
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.Deadline)
	defer cancel()

	id := make([]byte, 16)
	_, _ = rand.Read(id)
	ex := &execution{id: hex.EncodeToString(id), tenantID: req.TenantID, connectionID: req.ConnectionID}

	cmd := exec.Command(r.cfg.Node, "--permission", "--allow-fs-read="+filepath.Join(r.dir, "runner.mjs"),
		"--disallow-code-generation-from-strings", fmt.Sprintf("--max-old-space-size=%d", r.cfg.HeapMiB),
		"--stack-size=984", filepath.Join(r.dir, "runner.mjs"))
	cmd.Env, cmd.Dir = []string{}, r.dir
	cmd.Stderr = io.Discard // console output and Node diagnostics are discarded
	setProcAttr(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: starting node failed", ErrUnavailable)
	}
	exited := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
		case <-exited:
		}
	}()
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		close(exited)
	}()

	enc := json.NewEncoder(stdin)
	var encMu sync.Mutex
	send := func(m wireMessage) error {
		encMu.Lock()
		defer encMu.Unlock()
		return enc.Encode(m)
	}
	if err := send(wireMessage{Exec: ex.id, Source: req.Source, AccessToken: req.AccessToken, Context: req.Context}); err != nil {
		return nil, r.classify(ctx, fmt.Errorf("%w: runner did not accept the request", ErrProtocol))
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64<<10), maxOutputLine)
	var wg sync.WaitGroup
	defer wg.Wait()
	for sc.Scan() {
		var m wireMessage
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil || m.Exec != ex.id {
			return nil, fmt.Errorf("%w: malformed runner message", ErrProtocol)
		}
		switch m.Type {
		case "get":
			if m.Options == nil {
				return nil, fmt.Errorf("%w: malformed broker request", ErrProtocol)
			}
			wg.Add(1)
			go func(m wireMessage) {
				defer wg.Done()
				res, err := r.broker.get(ctx, ex, *m.Options)
				reply := wireMessage{Exec: ex.id, Type: "get_result", ID: m.ID}
				if err != nil {
					reply.Error = "request failed"
				} else {
					reply.Response, reply.Body = &res, &res.Body
				}
				_ = send(reply)
			}(m)
		case "done":
			if m.Error != "" {
				return nil, fmt.Errorf("%w: %s", ErrScript, safeReason(m.Error))
			}
			if len(m.Profile) == 0 || string(m.Profile) == "null" {
				return nil, fmt.Errorf("%w: no profile returned", ErrScript)
			}
			return m.Profile, nil
		default:
			return nil, fmt.Errorf("%w: unknown runner message", ErrProtocol)
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		return nil, fmt.Errorf("%w: runner output too large", ErrProtocol)
	}
	return nil, r.classify(ctx, fmt.Errorf("%w: script ended without calling back", ErrScript))
}

// classify turns an end of output into the deadline or cancellation that
// caused it, when one did.
func (r *Runner) classify(ctx context.Context, fallback error) error {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return ErrTimeout
	case errors.Is(ctx.Err(), context.Canceled):
		return context.Canceled
	}
	return fallback
}

// safeReason keeps only the runner's own fixed reason prefix, never script
// text: the runner reports error names, not messages, but a script can
// choose its error's name.
func safeReason(s string) string {
	for _, known := range []string{"script failed to compile", "fetchUserProfile is not defined", "callback called more than once", "script returned an error", "script threw"} {
		if strings.HasPrefix(s, known) {
			return known
		}
	}
	return "script failed"
}
