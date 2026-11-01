// Package customdb runs Auth0-style custom database scripts in Node.js.
//
// Each tenant gets its own long-lived Node process running runner.mjs,
// managed by a noderunner.Pool that only custom databases use. The process
// starts with an empty environment and Node's permission model, so scripts
// cannot read the host's environment variables, read files outside the
// runner and modules directories, or start processes (D-0022).
package customdb

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

//go:embed runner.mjs
var runnerJS []byte

// Request is one script execution.
type Request struct {
	TenantID     string
	ConnectionID string // vm context key, with ScriptHash
	Script       string // one of store.ScriptNames
	Source       string
	Config       map[string]string // plaintext configuration
	Args         []any             // JSON-encodable, without the callback
	// OnLogs, when set, receives the console output the script wrote during
	// this execution (at most maxCapturedLogs lines), once the script has
	// answered. It is not called when the execution fails without an answer.
	OnLogs func([]string)
}

// Executor runs custom database scripts. Result is the JSON value passed
// to the callback as its second argument ("null" when absent).
type Executor interface {
	Execute(ctx context.Context, req Request) (json.RawMessage, error)
	Close() error
}

const maxLogMsg = 2048 // bytes of one logged runner line

// NodeRunner is the Executor backed by Node.js processes, one per tenant.
type NodeRunner struct {
	pool        *noderunner.Pool
	log         *slog.Logger
	maxDuration time.Duration // MaxDuration; tests shorten it
	reapGrace   time.Duration // how long a reaped process may take to exit before it is killed
	maskPolicy  maskPolicy    // internal timing/limit injection; never public configuration

	mu    sync.Mutex
	procs map[string]*proc // by tenant ID; the log state of the processes taking new requests
}

var _ Executor = (*NodeRunner)(nil)

// NewNodeRunner prepares the runner pool; Node processes start on first
// use. Zero fields of cfg take the config defaults (node, 256 MB, 5m).
func NewNodeRunner(cfg config.CustomDB, log *slog.Logger) (*NodeRunner, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &NodeRunner{log: log, maxDuration: MaxDuration, reapGrace: 5 * time.Second, procs: map[string]*proc{}}
	modules := cfg.ModulesDir
	pool, err := noderunner.New(noderunner.Config{
		Node: cfg.Node, MaxMemoryMB: cfg.MaxMemoryMB, IdleTimeout: cfg.IdleTimeout,
		ReadDirs: func(string) []string { return []string{modules} },
		Args:     func(string) []string { return []string{modules} },
		Script:   runnerJS, Name: "custom database",
		Budget:    MaxDuration,
		ReapGrace: func() time.Duration { return r.reapGrace },
		OnStart:   r.started,
		OnRetire:  r.retired,
		OnStderr: func(tenant string, state any, line []byte) {
			r.logLine(state.(*proc), line)
		},
	}, log)
	if err != nil {
		return nil, fmt.Errorf("customdb: %w", err)
	}
	r.pool = pool
	return r, nil
}

// proc is the log state of one tenant's runner process.
type proc struct {
	tenant string

	mu           sync.Mutex
	policy       maskPolicy
	values       map[string]string // distinct detached values; key and value share storage
	configValues map[string]struct{}
	payloadBytes int
	masks        context.Context
	red          *Redactor
	deadline     time.Time
	timer        maskTimer
	muted        bool
}

func (r *NodeRunner) started(tenant string) any {
	p := &proc{tenant: tenant, policy: r.maskPolicy.defaults()}
	r.mu.Lock()
	r.procs[tenant] = p
	r.mu.Unlock()
	return p
}

func (r *NodeRunner) retired(tenant string, state any) {
	p := state.(*proc)
	p.mu.Lock()
	p.muteLocked()
	p.mu.Unlock()
	r.mu.Lock()
	if r.procs[tenant] == state {
		delete(r.procs, tenant)
	}
	r.mu.Unlock()
}

// checkNodeVersion accepts "vMAJOR.MINOR.PATCH" of Node 22.13 or later.
func checkNodeVersion(v string) error {
	if err := noderunner.CheckNodeVersion(v); err != nil {
		return unavailable(err)
	}
	return nil
}

// unavailable wraps a noderunner error in ErrUnavailable.
func unavailable(err error) error {
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// Probe checks once that the configured Node.js can run scripts and caches
// the answer; Execute calls it too. It starts no runner process. The error
// wraps ErrUnavailable.
func (r *NodeRunner) Probe() error {
	if err := r.pool.Probe(); err != nil {
		return unavailable(err)
	}
	return nil
}

// Wire protocol with runner.mjs. The pool adds the request "id".
type wireRequest struct {
	Conn   string            `json:"conn"`
	Hash   string            `json:"hash"`
	Name   string            `json:"name"`
	Source string            `json:"source"`
	Config map[string]string `json:"config"`
	Args   []any             `json:"args"`
	// Capture asks the runner to return the script's console output.
	Capture bool `json:"capture,omitempty"`
}

type wireError struct {
	Kind    string `json:"kind"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type response struct {
	ID     int64           `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  *wireError      `json:"error"`
	Logs   []string        `json:"logs"`
}

type logLine struct {
	Conn  string `json:"conn"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// Execute runs one script in the tenant's runner process.
func (r *NodeRunner) Execute(ctx context.Context, req Request) (json.RawMessage, error) {
	if !slices.Contains(store.ScriptNames, req.Script) {
		return nil, fmt.Errorf("customdb: unknown script %q", req.Script)
	}
	if req.Source == "" {
		return nil, ErrNoScript
	}
	if err := r.Probe(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(req.Source))
	wire := wireRequest{Conn: req.ConnectionID, Hash: hex.EncodeToString(sum[:]), Name: req.Script,
		Source: req.Source, Config: req.Config, Args: req.Args, Capture: req.OnLogs != nil}
	if wire.Config == nil {
		wire.Config = map[string]string{}
	}
	if wire.Args == nil {
		wire.Args = []any{}
	}
	var executed *proc
	raw, err := r.pool.CallWith(ctx, req.TenantID, wire, noderunner.CallOptions{
		Budget: r.maxDuration,
		Prepare: func(state any) {
			executed = state.(*proc)
			executed.registerMasks(ctx, req)
		},
		LogAttrs: []any{"connection", req.ConnectionID, "script", req.Script},
	})
	switch {
	case err == nil:
	case errors.Is(err, noderunner.ErrTimeout):
		return nil, ErrTimeout
	case errors.Is(err, noderunner.ErrUnavailable):
		return nil, unavailable(err)
	default:
		return nil, err
	}
	var resp response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("%w: invalid runner response", ErrUnavailable)
	}
	resp.Logs = executed.capture(resp.Logs)
	return deliver(req, resp)
}

// deliver hands resp's console output to req.OnLogs, then returns its result.
func deliver(req Request, resp response) (json.RawMessage, error) {
	if req.OnLogs != nil {
		req.OnLogs(resp.Logs)
	}
	return toResult(resp)
}

func toResult(resp response) (json.RawMessage, error) {
	if resp.OK {
		if len(resp.Result) == 0 {
			return json.RawMessage("null"), nil
		}
		return resp.Result, nil
	}
	se := &ScriptError{Kind: KindError}
	if resp.Error != nil {
		se.Code, se.Message = resp.Error.Code, resp.Error.Message
		switch resp.Error.Kind {
		case KindWrongCredentials, KindValidation, KindUnauthorized, KindError:
			se.Kind = resp.Error.Kind
		}
	}
	return nil, se
}

func (r *NodeRunner) logLine(p *proc, b []byte) {
	// Admit and scrub under the state lock, then hand only safe text to the
	// handler. A slow sink must not delay physical expiry or business requests.
	// An admitted safe line may finish emission after the process is muted.
	p.mu.Lock()
	if !p.diagnosticsLocked() {
		p.mu.Unlock()
		return
	}
	var l logLine
	if err := json.Unmarshal(b, &l); err != nil || l.Level == "" {
		out := p.scrubLocked(string(b))
		p.mu.Unlock()
		r.log.Warn("custom database runner output", "tenant", p.tenant, "output", truncateMaskedLine(out, maxLogMsg))
		return
	}
	msg := p.scrubLocked(l.Msg)
	p.mu.Unlock()
	level := slog.LevelInfo
	switch l.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	r.log.Log(context.Background(), level, "custom database script",
		"tenant", p.tenant, "connection", l.Conn, "output", truncateMaskedLine(msg, maxLogMsg))
}

// Close kills every runner process, including retired ones still running,
// and removes the temp dir.
func (r *NodeRunner) Close() error {
	if err := r.pool.Close(); err != nil {
		return fmt.Errorf("customdb: %w", err)
	}
	return nil
}

// truncateMaskedLine keeps the complete marker when redaction lengthens a line
// across the output byte cap. The source prefix is already scrubbed here.
func truncateMaskedLine(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := noderunner.Truncate(text, limit)
	for size := 1; size < len(logscrub.Marker); size++ {
		if strings.HasSuffix(cut, logscrub.Marker[:size]) {
			return noderunner.Truncate(strings.TrimSuffix(cut, logscrub.Marker[:size]), limit-len(logscrub.Marker)) + logscrub.Marker
		}
	}
	return cut
}
