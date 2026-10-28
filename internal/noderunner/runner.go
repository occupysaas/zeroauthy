// Package noderunner runs sandboxed Node.js processes for custom database
// scripts and Actions.
//
// A Pool keeps one long-lived Node process per tenant running the Pool's
// script. Each process starts with an empty environment and Node's
// permission model: file reads only in the script's private directory and
// the tenant's ReadDirs, no file writes, child processes, workers, addons or
// WASI (D-0022, spec §2). Custom databases and Actions own separate Pools,
// so killing one never affects the other.
//
// The protocol is newline-delimited JSON. The Pool adds an "id" member to
// each request object it writes to stdin; the script answers with one JSON
// object per stdout line carrying the same "id". stderr lines are the
// script's diagnostics.
package noderunner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	ErrTimeout     = errors.New("noderunner: call timed out")
	ErrUnavailable = errors.New("noderunner: node runtime unavailable") // node missing, too old, crashed
)

// DefaultBudget bounds one call unless the caller sets another. When it is
// exceeded the tenant's process is killed (Auth0's 20 s limit).
const DefaultBudget = 20 * time.Second

const (
	maxInFlight     = 64       // concurrent requests per tenant process
	maxResponseLine = 1 << 20  // bytes; a longer response kills the process
	maxLogMsg       = 2048     // bytes of one logged stderr line
	maxLogLine      = 16 << 10 // bytes of a stderr line read
	minReapTick     = 100 * time.Millisecond
)

// Config configures a Pool. Zero fields take defaults.
type Config struct {
	Node        string        // Node.js executable; default "node"
	MaxMemoryMB int           // --max-old-space-size; default 256
	IdleTimeout time.Duration // idle process lifetime; default 5m
	// ReadDirs lists the directories a tenant's process may read besides
	// the script's own; nil grants none.
	ReadDirs func(tenantID string) []string
	Script   []byte // the runner script (an ES module)
	Name     string // for log messages and the temp dir, e.g. "custom database"

	// Args lists the script's arguments (process.argv[2:]) for a tenant.
	Args func(tenantID string) []string
	// Budget is the default per-call limit; default DefaultBudget.
	Budget time.Duration
	// ReapGrace returns how long an idle process may take to exit after its
	// stdin closes before it is killed; default 5s. It is read at each reap.
	ReapGrace func() time.Duration
	// OnStart is called when a tenant's process starts (with the Pool's lock
	// held; it must not call the Pool) and returns state handed to
	// CallOptions.Prepare, OnStderr and OnRetire for that process.
	OnStart func(tenantID string) any
	// OnRetire is called once when a process stops taking new requests
	// (idle, killed or exited).
	OnRetire func(tenantID string, state any)
	// OnStderr receives each stderr line (at most 16 kB). Default: logged at
	// warn level, truncated.
	OnStderr func(tenantID string, state any, line []byte)
}

// CallOptions tune one call.
type CallOptions struct {
	Budget time.Duration // 0: the Pool's Budget
	// Prepare runs once the request is registered with a process, before it
	// is written, with that process's OnStart state.
	Prepare  func(state any)
	LogAttrs []any // added to the timeout warning
}

// Pool runs one Node process per tenant.
type Pool struct {
	cfg Config
	log *slog.Logger
	dir string // 0700 temp dir holding the script

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

// New writes the script to a private temp dir and starts the idle reaper;
// processes start on first use.
func New(cfg Config, log *slog.Logger) (*Pool, error) {
	if cfg.Node == "" {
		cfg.Node = "node"
	}
	if cfg.MaxMemoryMB <= 0 {
		cfg.MaxMemoryMB = 256
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.Budget <= 0 {
		cfg.Budget = DefaultBudget
	}
	if cfg.Name == "" {
		cfg.Name = "node"
	}
	if log == nil {
		log = slog.Default()
	}
	dir, err := os.MkdirTemp("", "zeroauthy-noderunner-")
	if err != nil {
		return nil, fmt.Errorf("noderunner: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("noderunner: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runner.mjs"), cfg.Script, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("noderunner: %w", err)
	}
	p := &Pool{
		cfg: cfg, log: log, dir: dir,
		procs: map[string]*proc{}, live: map[*proc]struct{}{}, stop: make(chan struct{}), reaperDone: make(chan struct{}),
	}
	go p.reaper()
	return p, nil
}

// Probe checks once that the configured Node.js is usable and caches the
// answer; Call runs it too. It starts no runner process. The error wraps
// ErrUnavailable.
func (p *Pool) Probe() error {
	p.probeOnce.Do(func() {
		rt, err := detect(p.cfg.Node, p.dir)
		p.probeErr, p.allowNet = err, rt.AllowNet
	})
	return p.probeErr
}

// proc is one tenant's process.
type proc struct {
	tenant string
	state  any // from Config.OnStart
	cmd    *exec.Cmd
	sem    chan struct{} // in-flight request slots
	done   chan struct{} // closed when the process has exited

	wmu   sync.Mutex // serialises stdin writes
	stdin io.WriteCloser

	mu       sync.Mutex
	pending  map[int64]chan []byte
	nextID   int64
	lastUsed time.Time
	retired  bool // takes no new requests; no longer in Pool.procs
}

func (pr *proc) write(line []byte) error {
	pr.wmu.Lock()
	defer pr.wmu.Unlock()
	_, err := pr.stdin.Write(line)
	return err
}

func (pr *proc) unregister(id int64) {
	pr.mu.Lock()
	delete(pr.pending, id)
	pr.lastUsed = time.Now()
	pr.mu.Unlock()
}

// Call sends req (which must encode to a JSON object without an "id"
// member) to the tenant's process and returns the response line, within the
// Pool's Budget.
func (p *Pool) Call(ctx context.Context, tenantID string, req any) (json.RawMessage, error) {
	return p.CallWith(ctx, tenantID, req, CallOptions{})
}

// CallWith is Call with options. When ctx ends first the call returns
// ctx.Err() but the request stays pending, still bounded by the budget:
// the process is killed if the script does not answer in time. Exceeding
// the budget kills the tenant's process, failing its other in-flight calls,
// and returns ErrTimeout.
func (p *Pool) CallWith(ctx context.Context, tenantID string, req any, opts CallOptions) (json.RawMessage, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("noderunner: encoding request: %w", err)
	}
	body = bytes.TrimSpace(body)
	if len(body) < 2 || body[0] != '{' {
		return nil, errors.New("noderunner: request is not a JSON object")
	}
	// The Pool owns "id": a request carrying its own would never match its
	// answer and would wait out the whole budget.
	// Decoding into a one-field struct keeps no other member. It also
	// matches "ID" or "Id" (encoding/json folds case), which no request
	// uses; refusing those too is harmless.
	var reserved struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(body, &reserved); err != nil {
		return nil, errors.New("noderunner: request is not a JSON object")
	}
	if reserved.ID != nil {
		return nil, errors.New(`noderunner: the request member "id" is reserved`)
	}
	if err := p.Probe(); err != nil {
		return nil, err
	}
	budget := opts.Budget
	if budget <= 0 {
		budget = p.cfg.Budget
	}

	// The timer is owned by await, which may hand it to a watcher.
	timer := time.NewTimer(budget)

	// A process retired between lookup and registration is replaced; retry.
	for range 3 {
		pr, err := p.getProc(tenantID)
		if err != nil {
			timer.Stop()
			return nil, err
		}
		select {
		case pr.sem <- struct{}{}:
		case <-pr.done:
			continue
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			return nil, ErrTimeout
		}
		pr.mu.Lock()
		if pr.retired {
			pr.mu.Unlock()
			<-pr.sem
			continue
		}
		pr.nextID++
		id := pr.nextID
		ch := make(chan []byte, 1)
		pr.pending[id] = ch
		pr.lastUsed = time.Now()
		pr.mu.Unlock()
		if opts.Prepare != nil {
			opts.Prepare(pr.state)
		}
		line := withID(body, id)
		return p.await(ctx, pr, id, line, ch, timer, opts.LogAttrs)
	}
	timer.Stop()
	return nil, fmt.Errorf("%w: runner process keeps exiting", ErrUnavailable)
}

// withID returns the object body with "id":id as its first member, newline
// terminated.
func withID(body []byte, id int64) []byte {
	line := make([]byte, 0, len(body)+32)
	line = append(line, `{"id":`...)
	line = strconv.AppendInt(line, id, 10)
	rest := bytes.TrimSpace(body[1:])
	if len(rest) > 0 && rest[0] != '}' {
		line = append(line, ',')
	}
	line = append(line, rest...)
	return append(line, '\n')
}

// await waits for the response to a registered request. It owns pr's
// semaphore slot and timer; if the caller leaves early, a watcher takes them
// over so the request stays bounded by the budget.
func (p *Pool) await(ctx context.Context, pr *proc, id int64, line []byte, ch chan []byte, timer *time.Timer, attrs []any) (json.RawMessage, error) {
	handedOff := false
	defer func() {
		if !handedOff {
			timer.Stop()
			<-pr.sem
		}
	}()
	// Write asynchronously: a busy script stops reading stdin, and a large
	// request must not block past the deadline.
	errc := make(chan error, 1)
	go func() { errc <- pr.write(line) }()
	for {
		select {
		case resp := <-ch:
			return resp, nil
		case err := <-errc:
			if err != nil {
				pr.unregister(id)
				return nil, fmt.Errorf("%w: writing to runner: %v", ErrUnavailable, err)
			}
			errc = nil
		case <-pr.done:
			select {
			case resp := <-ch:
				return resp, nil
			default:
				return nil, fmt.Errorf("%w: runner process exited", ErrUnavailable)
			}
		case <-ctx.Done():
			// The script keeps running: leave it pending (the reaper must not
			// retire its process) and still enforce the deadline.
			handedOff = true
			go p.watch(pr, id, ch, errc, timer, attrs)
			return nil, ctx.Err()
		case <-timer.C:
			p.timedOut(pr, id, attrs)
			return nil, ErrTimeout
		}
	}
}

// watch finishes a request whose caller has gone: it drops the response, or
// kills the process at the deadline.
func (p *Pool) watch(pr *proc, id int64, ch chan []byte, errc chan error, timer *time.Timer, attrs []any) {
	defer func() {
		timer.Stop()
		<-pr.sem
	}()
	for {
		select {
		case <-ch:
			return
		case err := <-errc:
			if err != nil {
				pr.unregister(id)
				return
			}
			errc = nil
		case <-pr.done:
			return
		case <-timer.C:
			p.timedOut(pr, id, attrs)
			return
		}
	}
}

func (p *Pool) timedOut(pr *proc, id int64, attrs []any) {
	pr.unregister(id)
	p.log.Warn(p.cfg.Name+" call timed out; killing the tenant's runner", append([]any{"tenant", pr.tenant}, attrs...)...)
	p.kill(pr)
}

func (p *Pool) getProc(tenant string) (*proc, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, fmt.Errorf("%w: runner closed", ErrUnavailable)
	}
	if pr := p.procs[tenant]; pr != nil {
		return pr, nil
	}
	pr, err := p.start(tenant)
	if err != nil {
		return nil, err
	}
	p.procs[tenant] = pr
	return pr, nil
}

// start launches a process for tenant. Called with p.mu held.
func (p *Pool) start(tenant string) (*proc, error) {
	reads := []string{p.dir}
	if p.cfg.ReadDirs != nil {
		reads = append(reads, p.cfg.ReadDirs(tenant)...)
	}
	args := []string{fmt.Sprintf("--max-old-space-size=%d", p.cfg.MaxMemoryMB), filepath.Join(p.dir, "runner.mjs")}
	if p.cfg.Args != nil {
		args = append(args, p.cfg.Args(tenant)...)
	}
	cmd := exec.Command(p.cfg.Node, args...)
	Sandbox(cmd, reads, nil, p.allowNet)
	cmd.Dir = p.dir
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
	pr := &proc{
		tenant: tenant, cmd: cmd, stdin: stdin,
		sem: make(chan struct{}, maxInFlight), done: make(chan struct{}),
		pending: map[int64]chan []byte{}, lastUsed: time.Now(),
	}
	if p.cfg.OnStart != nil {
		pr.state = p.cfg.OnStart(tenant)
	}
	p.live[pr] = struct{}{}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); p.readResponses(pr, stdout) }()
	go func() { defer readers.Done(); p.readStderr(pr, stderr) }()
	go func() {
		readers.Wait()
		_ = cmd.Wait()
		p.exited(pr)
	}()
	return pr, nil
}

func (p *Pool) readResponses(pr *proc, rd io.Reader) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64<<10), maxResponseLine)
	for sc.Scan() {
		var head struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(sc.Bytes(), &head); err != nil {
			p.log.Warn(p.cfg.Name+" runner wrote an invalid response line", "tenant", pr.tenant)
			continue
		}
		pr.mu.Lock()
		ch := pr.pending[head.ID]
		delete(pr.pending, head.ID)
		pr.lastUsed = time.Now()
		pr.mu.Unlock()
		if ch != nil {
			ch <- bytes.Clone(sc.Bytes()) // buffered; one response per id
		}
	}
	if err := sc.Err(); err != nil {
		p.log.Warn(p.cfg.Name+" runner response unreadable; killing the tenant's runner", "tenant", pr.tenant, "error", err)
		p.kill(pr)
		_, _ = io.Copy(io.Discard, rd)
	}
}

func (p *Pool) readStderr(pr *proc, rd io.Reader) {
	br := bufio.NewReaderSize(rd, 64<<10)
	var buf []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if len(buf) < maxLogLine {
			buf = append(buf, chunk...)
		}
		if err != nil {
			return
		}
		if isPrefix {
			continue
		}
		if len(buf) > 0 {
			if p.cfg.OnStderr != nil {
				p.cfg.OnStderr(pr.tenant, pr.state, buf)
			} else {
				p.log.Warn(p.cfg.Name+" runner output", "tenant", pr.tenant, "output", Truncate(string(buf), maxLogMsg))
			}
		}
		buf = buf[:0]
	}
}

// Truncate cuts s to at most n bytes on a rune boundary.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// retire stops new requests reaching pr and drops it from p.procs.
func (p *Pool) retire(pr *proc) {
	p.mu.Lock()
	if p.procs[pr.tenant] == pr {
		delete(p.procs, pr.tenant)
	}
	p.mu.Unlock()
	pr.mu.Lock()
	first := !pr.retired
	pr.retired = true
	pr.mu.Unlock()
	if first {
		p.retired(pr)
	}
}

// retired reports pr's retirement to OnRetire.
func (p *Pool) retired(pr *proc) {
	if p.cfg.OnRetire != nil {
		p.cfg.OnRetire(pr.tenant, pr.state)
	}
}

func (p *Pool) kill(pr *proc) {
	p.retire(pr)
	_ = pr.cmd.Process.Kill()
}

func (p *Pool) exited(pr *proc) {
	p.retire(pr)
	p.mu.Lock()
	delete(p.live, pr)
	p.mu.Unlock()
	close(pr.done)
}

func (p *Pool) reapGrace() time.Duration {
	if p.cfg.ReapGrace != nil {
		if d := p.cfg.ReapGrace(); d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

// reaper closes the stdin of processes idle past IdleTimeout; the runner
// exits when its stdin closes, or is killed after the reap grace if it does
// not (a script still busy from a timer, say). A process with any pending
// request, including one whose caller has gone, is not idle.
func (p *Pool) reaper() {
	defer close(p.reaperDone)
	t := time.NewTicker(max(p.cfg.IdleTimeout/2, minReapTick))
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case now := <-t.C:
			var idle []*proc
			p.mu.Lock()
			for tenant, pr := range p.procs {
				pr.mu.Lock()
				if len(pr.pending) == 0 && now.Sub(pr.lastUsed) >= p.cfg.IdleTimeout {
					pr.retired = true
					delete(p.procs, tenant)
					idle = append(idle, pr)
				}
				pr.mu.Unlock()
			}
			p.mu.Unlock()
			for _, pr := range idle {
				p.retired(pr)
				go func() {
					pr.wmu.Lock()
					defer pr.wmu.Unlock()
					_ = pr.stdin.Close()
				}()
				go func() {
					grace := time.NewTimer(p.reapGrace())
					defer grace.Stop()
					select {
					case <-pr.done:
					case <-grace.C:
						p.log.Warn("idle "+p.cfg.Name+" runner did not exit; killing it", "tenant", pr.tenant)
						p.kill(pr)
					}
				}()
			}
		}
	}
}

// Close kills every process, including retired ones still running, and
// removes the temp dir.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	procs := make([]*proc, 0, len(p.live))
	for pr := range p.live {
		procs = append(procs, pr)
	}
	p.mu.Unlock()
	close(p.stop)
	<-p.reaperDone
	for _, pr := range procs {
		p.kill(pr)
	}
	for _, pr := range procs {
		<-pr.done
	}
	if err := os.RemoveAll(p.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("noderunner: %w", err)
	}
	return nil
}
