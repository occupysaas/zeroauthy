// Package customdb runs Auth0-style custom database scripts in Node.js.
//
// Each tenant gets its own long-lived Node process running runner.mjs. The
// process starts with an empty environment and Node's permission model, so
// scripts cannot read the host's environment variables, read files outside
// the runner and modules directories, or start processes (D-0022).
package customdb

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
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

const (
	maxInFlight     = 64      // concurrent requests per tenant process
	maxResponseLine = 1 << 20 // bytes; a longer response kills the process
	maxLogMsg       = 2048    // bytes of one logged runner line
	minReapTick     = 100 * time.Millisecond
)

// NodeRunner is the Executor backed by Node.js processes, one per tenant.
type NodeRunner struct {
	cfg         config.CustomDB
	log         *slog.Logger
	dir         string        // 0700 temp dir holding runner.mjs
	maxDuration time.Duration // MaxDuration; tests shorten it

	reapGrace time.Duration // how long a reaped process may take to exit before it is killed

	mu     sync.Mutex
	procs  map[string]*proc   // by tenant ID; the processes taking new requests
	live   map[*proc]struct{} // every started process until it has exited
	closed bool

	probeOnce sync.Once
	probeErr  error
	allowNet  bool

	stop       chan struct{}
	reaperDone chan struct{}
}

var _ Executor = (*NodeRunner)(nil)

// NewNodeRunner writes runner.mjs to a private temp dir and starts the idle
// reaper; Node processes start on first use. Zero fields of cfg take the
// config defaults (node, 256 MB, 5m).
func NewNodeRunner(cfg config.CustomDB, log *slog.Logger) (*NodeRunner, error) {
	if cfg.Node == "" {
		cfg.Node = "node"
	}
	if cfg.MaxMemoryMB <= 0 {
		cfg.MaxMemoryMB = 256
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	dir, err := os.MkdirTemp("", "zeroauthy-customdb-")
	if err != nil {
		return nil, fmt.Errorf("customdb: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("customdb: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runner.mjs"), runnerJS, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("customdb: %w", err)
	}
	r := &NodeRunner{
		cfg: cfg, log: log, dir: dir, maxDuration: MaxDuration, reapGrace: 5 * time.Second,
		procs: map[string]*proc{}, live: map[*proc]struct{}{}, stop: make(chan struct{}), reaperDone: make(chan struct{}),
	}
	go r.reaper()
	return r, nil
}

// checkNodeVersion accepts "vMAJOR.MINOR.PATCH" of Node 22.13 or later.
func checkNodeVersion(v string) error {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("%w: unrecognised node version %q", ErrUnavailable, v)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return fmt.Errorf("%w: unrecognised node version %q", ErrUnavailable, v)
	}
	if major > 22 || (major == 22 && minor >= 13) {
		return nil
	}
	return fmt.Errorf("%w: node %s is too old; custom database scripts need 22.13 or later", ErrUnavailable, v)
}

// probe checks the Node version and whether --allow-net exists (Node 25+
// denies network access under --permission without it; Node 22 lacks the
// flag and does not restrict the network).
func (r *NodeRunner) probe() error {
	cmd := exec.Command(r.cfg.Node, "--version")
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%w: running %s --version: %v", ErrUnavailable, r.cfg.Node, err)
	}
	if err := checkNodeVersion(strings.TrimSpace(string(out))); err != nil {
		return err
	}
	net := exec.Command(r.cfg.Node, "--permission", "--allow-net", "-e", "0")
	net.Env = []string{}
	net.Dir = r.dir
	r.allowNet = net.Run() == nil
	return nil
}

// Probe checks once that the configured Node.js can run scripts and caches
// the answer; Execute calls it too. It starts no runner process. The error
// wraps ErrUnavailable.
func (r *NodeRunner) Probe() error {
	r.probeOnce.Do(func() { r.probeErr = r.probe() })
	return r.probeErr
}

// Wire protocol with runner.mjs.
type wireRequest struct {
	ID     int64             `json:"id"`
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

// proc is one tenant's runner process.
type proc struct {
	tenant string
	cmd    *exec.Cmd
	sem    chan struct{} // in-flight request slots
	done   chan struct{} // closed when the process has exited

	wmu   sync.Mutex // serialises stdin writes
	stdin io.WriteCloser

	mu       sync.Mutex
	pending  map[int64]chan response
	nextID   int64
	lastUsed time.Time
	retired  bool // takes no new requests; no longer in NodeRunner.procs
	// reds masks each connection's configuration values in the script
	// console lines logged for it. Entries stay after a request ends: the
	// runner's stderr is read apart from its answers, so a line can be
	// logged after the answer.
	reds map[string]*Redactor
}

func (p *proc) write(line []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	_, err := p.stdin.Write(line)
	return err
}

func (p *proc) unregister(id int64) {
	p.mu.Lock()
	delete(p.pending, id)
	p.lastUsed = time.Now()
	p.mu.Unlock()
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

	// The timer is owned by await, which may hand it to a watcher.
	timer := time.NewTimer(r.maxDuration)

	// A process retired between lookup and registration is replaced; retry.
	for range 3 {
		p, err := r.getProc(req.TenantID)
		if err != nil {
			timer.Stop()
			return nil, err
		}
		select {
		case p.sem <- struct{}{}:
		case <-p.done:
			continue
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrTimeout
		}
		p.mu.Lock()
		if p.retired {
			p.mu.Unlock()
			<-p.sem
			continue
		}
		p.nextID++
		wire.ID = p.nextID
		ch := make(chan response, 1)
		p.pending[wire.ID] = ch
		if p.reds == nil {
			p.reds = map[string]*Redactor{}
		}
		p.reds[req.ConnectionID] = NewRedactor(req.Config)
		p.lastUsed = time.Now()
		p.mu.Unlock()

		return r.await(ctx, p, req, wire, ch, timer)
	}
	timer.Stop()
	return nil, fmt.Errorf("%w: runner process keeps exiting", ErrUnavailable)
}

// await waits for the response to a registered request. It owns p's
// semaphore slot and timer; if the caller leaves early, a watcher takes them
// over so the request stays bounded by the deadline.
func (r *NodeRunner) await(ctx context.Context, p *proc, req Request, wire wireRequest, ch chan response, timer *time.Timer) (json.RawMessage, error) {
	handedOff := false
	defer func() {
		if !handedOff {
			timer.Stop()
			<-p.sem
		}
	}()
	line, err := json.Marshal(wire)
	if err != nil {
		p.unregister(wire.ID)
		return nil, fmt.Errorf("customdb: encoding request: %w", err)
	}
	// Write asynchronously: a busy script stops reading stdin, and a large
	// request must not block past the deadline.
	errc := make(chan error, 1)
	go func() { errc <- p.write(append(line, '\n')) }()
	for {
		select {
		case resp := <-ch:
			return deliver(req, resp)
		case err := <-errc:
			if err != nil {
				p.unregister(wire.ID)
				return nil, fmt.Errorf("%w: writing to runner: %v", ErrUnavailable, err)
			}
			errc = nil
		case <-p.done:
			select {
			case resp := <-ch:
				return deliver(req, resp)
			default:
				return nil, fmt.Errorf("%w: runner process exited", ErrUnavailable)
			}
		case <-ctx.Done():
			// The script keeps running: leave it pending (the reaper must not
			// retire its process) and still enforce the deadline.
			handedOff = true
			go r.watch(p, req, wire.ID, ch, errc, timer)
			return nil, ctx.Err()
		case <-timer.C:
			r.timedOut(p, req, wire.ID)
			return nil, ErrTimeout
		}
	}
}

// watch finishes a request whose caller has gone: it drops the response, or
// kills the process at the deadline.
func (r *NodeRunner) watch(p *proc, req Request, id int64, ch chan response, errc chan error, timer *time.Timer) {
	defer func() {
		timer.Stop()
		<-p.sem
	}()
	for {
		select {
		case <-ch:
			return
		case err := <-errc:
			if err != nil {
				p.unregister(id)
				return
			}
			errc = nil
		case <-p.done:
			return
		case <-timer.C:
			r.timedOut(p, req, id)
			return
		}
	}
}

func (r *NodeRunner) timedOut(p *proc, req Request, id int64) {
	p.unregister(id)
	r.log.Warn("custom database script timed out; killing the tenant's runner",
		"tenant", req.TenantID, "connection", req.ConnectionID, "script", req.Script)
	r.kill(p)
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

func (r *NodeRunner) getProc(tenant string) (*proc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, fmt.Errorf("%w: runner closed", ErrUnavailable)
	}
	if p := r.procs[tenant]; p != nil {
		return p, nil
	}
	p, err := r.start(tenant)
	if err != nil {
		return nil, err
	}
	r.procs[tenant] = p
	return p, nil
}

// start launches a runner process for tenant. Called with r.mu held.
func (r *NodeRunner) start(tenant string) (*proc, error) {
	args := []string{"--permission", "--allow-fs-read=" + r.dir}
	if r.cfg.ModulesDir != "" {
		args = append(args, "--allow-fs-read="+r.cfg.ModulesDir)
	}
	if r.allowNet {
		args = append(args, "--allow-net", "--disable-warning=ExperimentalWarning")
	}
	args = append(args, fmt.Sprintf("--max-old-space-size=%d", r.cfg.MaxMemoryMB), filepath.Join(r.dir, "runner.mjs"), r.cfg.ModulesDir)
	cmd := exec.Command(r.cfg.Node, args...)
	cmd.Env = []string{} // never inherit the host environment (D-0022)
	cmd.Dir = r.dir
	setProcAttr(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: starting node: %v", ErrUnavailable, err)
	}
	p := &proc{
		tenant: tenant, cmd: cmd, stdin: stdin,
		sem: make(chan struct{}, maxInFlight), done: make(chan struct{}),
		pending: map[int64]chan response{}, lastUsed: time.Now(),
	}
	r.live[p] = struct{}{}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); r.readResponses(p, stdout) }()
	go func() { defer readers.Done(); r.readLogs(p, stderr) }()
	go func() {
		readers.Wait()
		_ = cmd.Wait()
		r.exited(p)
	}()
	return p, nil
}

func (r *NodeRunner) readResponses(p *proc, rd io.Reader) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64<<10), maxResponseLine)
	for sc.Scan() {
		var resp response
		if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
			r.log.Warn("custom database runner wrote an invalid response line", "tenant", p.tenant)
			continue
		}
		p.mu.Lock()
		ch := p.pending[resp.ID]
		delete(p.pending, resp.ID)
		p.lastUsed = time.Now()
		p.mu.Unlock()
		if ch != nil {
			ch <- resp // buffered; one response per id
		}
	}
	if err := sc.Err(); err != nil {
		r.log.Warn("custom database runner response unreadable; killing the tenant's runner", "tenant", p.tenant, "error", err)
		r.kill(p)
		_, _ = io.Copy(io.Discard, rd)
	}
}

func (r *NodeRunner) readLogs(p *proc, rd io.Reader) {
	br := bufio.NewReaderSize(rd, 64<<10)
	var buf []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if len(buf) < maxLogMsg*4 {
			buf = append(buf, chunk...)
		}
		if err != nil {
			return
		}
		if isPrefix {
			continue
		}
		r.logLine(p, buf)
		buf = buf[:0]
	}
}

func (r *NodeRunner) logLine(p *proc, b []byte) {
	if len(b) == 0 {
		return
	}
	var l logLine
	if err := json.Unmarshal(b, &l); err != nil || l.Level == "" {
		// Unstructured output could carry any connection's values.
		out := string(b)
		for _, red := range p.redactors() {
			out = red.Redact(out)
		}
		r.log.Warn("custom database runner output", "tenant", p.tenant, "output", truncate(out, maxLogMsg))
		return
	}
	// Mask before truncating, so a cut never leaves a prefix of a value.
	msg := p.redactorFor(l.Conn).Redact(l.Msg)
	level := slog.LevelInfo
	switch l.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	// "output", not "msg": the record's own message already uses that key.
	r.log.Log(context.Background(), level, "custom database script",
		"tenant", p.tenant, "connection", l.Conn, "output", truncate(msg, maxLogMsg))
}

func (p *proc) redactorFor(conn string) *Redactor {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reds[conn]
}

func (p *proc) redactors() []*Redactor {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Redactor, 0, len(p.reds))
	for _, r := range p.reds {
		out = append(out, r)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// retire stops new requests reaching p and drops it from r.procs.
func (r *NodeRunner) retire(p *proc) {
	r.mu.Lock()
	if r.procs[p.tenant] == p {
		delete(r.procs, p.tenant)
	}
	r.mu.Unlock()
	p.mu.Lock()
	p.retired = true
	p.mu.Unlock()
}

func (r *NodeRunner) kill(p *proc) {
	r.retire(p)
	_ = p.cmd.Process.Kill()
}

func (r *NodeRunner) exited(p *proc) {
	r.retire(p)
	r.mu.Lock()
	delete(r.live, p)
	r.mu.Unlock()
	close(p.done)
}

// reaper closes the stdin of processes idle past IdleTimeout; the runner
// exits when its stdin closes, or is killed after reapGrace if it does not
// (a script still busy from a timer, say). A process with any pending
// request, including one whose caller has gone, is not idle.
func (r *NodeRunner) reaper() {
	defer close(r.reaperDone)
	t := time.NewTicker(max(r.cfg.IdleTimeout/2, minReapTick))
	defer t.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-t.C:
			var idle []*proc
			r.mu.Lock()
			for tenant, p := range r.procs {
				p.mu.Lock()
				if len(p.pending) == 0 && now.Sub(p.lastUsed) >= r.cfg.IdleTimeout {
					p.retired = true
					delete(r.procs, tenant)
					idle = append(idle, p)
				}
				p.mu.Unlock()
			}
			r.mu.Unlock()
			for _, p := range idle {
				go func() {
					p.wmu.Lock()
					defer p.wmu.Unlock()
					_ = p.stdin.Close()
				}()
				go func() {
					grace := time.NewTimer(r.reapGrace)
					defer grace.Stop()
					select {
					case <-p.done:
					case <-grace.C:
						r.log.Warn("idle custom database runner did not exit; killing it", "tenant", p.tenant)
						r.kill(p)
					}
				}()
			}
		}
	}
}

// Close kills every runner process, including retired ones still running,
// and removes the temp dir.
func (r *NodeRunner) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	procs := make([]*proc, 0, len(r.live))
	for p := range r.live {
		procs = append(procs, p)
	}
	r.mu.Unlock()
	close(r.stop)
	<-r.reaperDone
	for _, p := range procs {
		r.kill(p)
	}
	for _, p := range procs {
		<-p.done
	}
	if err := os.RemoveAll(r.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("customdb: %w", err)
	}
	return nil
}
