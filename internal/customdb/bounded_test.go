package customdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

// Without a cap, a busy process retains every password forever and keeps
// delivering console diagnostics after it can no longer retain them safely.
func TestRunnerBoundedMasksMuteAtCapacity(t *testing.T) {
	var sink syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&sink, nil)))
	req := Request{TenantID: "bounded", ConnectionID: "c", Script: "login", Source: `function login(e,p,cb){globalThis.old ??= p; console.log("cached",globalThis.old); cb(null,{ok:true});}`}
	for i := 0; i < 270; i++ {
		req.Args = []any{"a", fmt.Sprintf("credential-%03d", i)}
		var lines []string
		req.OnLogs = func(v []string) { lines = v }
		raw, err := r.Execute(context.Background(), req)
		if err != nil || string(raw) != `{"ok":true}` {
			t.Fatalf("call %d result=%s err=%v", i, raw, err)
		}
		if i >= 256 && len(lines) != 0 {
			t.Fatalf("call %d: console continued after capacity: %q", i, lines)
		}
		r.mu.Lock()
		p := r.procs["bounded"]
		r.mu.Unlock()
		p.mu.Lock()
		count, payload := len(p.values), p.payloadBytes
		p.mu.Unlock()
		if count > 256 || payload > 64<<10 {
			t.Fatalf("call %d retained count=%d payload=%d", i, count, payload)
		}
		if i >= 256 {
			assertMasksCleared(t, p)
		}
	}
	if strings.Contains(sink.String(), "credential-") {
		t.Fatal("cached password leaked")
	}
}

// These tests catch clearing only at the next lookup, reset-on-every-request
// deadlines, independent configuration/credential budgets, and stale snapshots
// being logged after retirement. Time advances without sleeps or pool reaping.
type maskTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*maskTestTimer
}
type maskTestTimer struct {
	clock    *maskTestClock
	at       time.Time
	callback func()
	stopped  bool
}

func (c *maskTestClock) policy(values, bytes int) maskPolicy {
	return maskPolicy{maxValues: values, maxBytes: bytes, retention: time.Minute,
		now: func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now },
		afterFunc: func(d time.Duration, f func()) maskTimer {
			c.mu.Lock()
			defer c.mu.Unlock()
			timer := &maskTestTimer{clock: c, at: c.now.Add(d), callback: f}
			c.timers = append(c.timers, timer)
			return timer
		}}
}
func (t *maskTestTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}
func (c *maskTestClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var callbacks []func()
	for _, timer := range c.timers {
		if !timer.stopped && !timer.at.After(c.now) {
			timer.stopped = true
			callbacks = append(callbacks, timer.callback)
		}
	}
	c.mu.Unlock()
	for _, f := range callbacks {
		f()
	}
}
func newMaskTestProcess(values, bytes int) (*proc, *maskTestClock) {
	c := &maskTestClock{now: time.Unix(100, 0)}
	return &proc{policy: c.policy(values, bytes)}, c
}
func assertMasksCleared(t *testing.T, p *proc) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.muted || len(p.values) != 0 || len(p.configValues) != 0 || p.payloadBytes != 0 || p.masks != nil || p.red != nil || p.timer != nil {
		t.Fatalf("mask state not physically cleared: muted=%v values=%d configured=%d bytes=%d", p.muted, len(p.values), len(p.configValues), p.payloadBytes)
	}
}
func TestProcessMasksBoundedUnion(t *testing.T) {
	p, c := newMaskTestProcess(3, 10)
	ctx := logscrub.WithCredentials(context.Background(), "猫", "ab")
	req := Request{Config: map[string]string{"duplicate": "猫", "key": "cfg"}}
	p.registerMasks(ctx, req)
	if len(p.values) != 3 || p.payloadBytes != 8 {
		t.Fatalf("distinct=%d payload=%d", len(p.values), p.payloadBytes)
	}
	if got := p.capture([]string{"ab cfg"}); len(got) != 1 || got[0] != logscrub.Marker+" "+Mask {
		t.Fatalf("capture=%q", got)
	}
	c.advance(59 * time.Second)
	p.registerMasks(ctx, req) // duplicate values share one allowance and don't reset time
	if len(c.timers) != 1 {
		t.Fatalf("timers=%d", len(c.timers))
	}
	p.registerMasks(logscrub.WithCredentials(context.Background(), "new"), Request{})
	assertMasksCleared(t, p)
	p.registerMasks(ctx, req)
	if got := p.capture([]string{"ab cfg"}); len(got) != 0 {
		t.Fatalf("muted process resumed: %q", got)
	}
	assertMasksCleared(t, p)
}
func TestProcessMasksDeadlineClearsWithoutLookup(t *testing.T) {
	p, c := newMaskTestProcess(3, 20)
	p.registerMasks(context.Background(), Request{})
	if len(c.timers) != 0 {
		t.Fatal("empty request started retention timer")
	}
	p.registerMasks(logscrub.WithCredentials(context.Background(), "a", "bc", "猫"), Request{})
	c.advance(59 * time.Second)
	p.registerMasks(context.Background(), Request{Config: map[string]string{"key": "bc"}})
	c.advance(time.Second)
	assertMasksCleared(t, p) // no diagnostic lookup or idle retirement triggers expiry
	var sink syncBuffer
	r := &NodeRunner{log: slog.New(slog.NewJSONHandler(&sink, nil))}
	r.logLine(p, []byte("a bc 猫"))
	r.logLine(p, []byte(`{"conn":"unknown","level":"info","msg":"a bc 猫"}`))
	if sink.String() != "" {
		t.Fatalf("muted stderr=%s", sink.String())
	}
}
func TestProcessMasksPayloadLimit(t *testing.T) {
	for _, first := range []string{"abcd", strings.Repeat("z", 1<<20)} {
		p, c := newMaskTestProcess(256, 4)
		p.registerMasks(logscrub.WithCredentials(context.Background(), first), Request{})
		if len(first) == 4 {
			if p.payloadBytes != 4 {
				t.Fatalf("payload=%d", p.payloadBytes)
			}
			p.registerMasks(context.Background(), Request{Config: map[string]string{"key": "e"}})
		} else if len(c.timers) != 0 {
			t.Fatal("oversized single value retained a timer")
		}
		assertMasksCleared(t, p)
	}
}
func TestProcessMasksRetirementCancelsTimer(t *testing.T) {
	p, c := newMaskTestProcess(3, 20)
	p.registerMasks(logscrub.WithCredentials(context.Background(), "secret"), Request{})
	r := &NodeRunner{procs: map[string]*proc{"t": p}}
	r.retired("t", p)
	assertMasksCleared(t, p)
	if !c.timers[0].stopped {
		t.Fatal("retirement left timer running")
	}
	// A timer that already entered its callback can race retirement; it remains
	// idempotent and cannot revive state or leak output.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.timers[0].callback()
			p.registerMasks(context.Background(), Request{Config: map[string]string{"k": "other"}})
			p.capture([]string{"secret"})
		}()
	}
	wg.Wait()
	assertMasksCleared(t, p)
}

func TestRunnerBoundedMasksMixedConfigAndCredentials(t *testing.T) {
	var sink syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&sink, nil)))
	r.maskPolicy = maskPolicy{maxValues: 3}
	req := Request{TenantID: "mixed", ConnectionID: "c", Script: "login", Source: `function login(e,p,cb){globalThis.old??=p;globalThis.cfg??=configuration.K;console.log("old",globalThis.old,globalThis.cfg);cb(null,{ok:true});}`, Config: map[string]string{"K": "configured-old"}, Args: []any{"a", "猫"}}
	var lines []string
	req.OnLogs = func(v []string) { lines = v }
	run := func() {
		raw, err := r.Execute(context.Background(), req)
		if err != nil || string(raw) != `{"ok":true}` {
			t.Fatalf("raw=%s err=%v", raw, err)
		}
	}
	run()
	if len(lines) != 1 || strings.Contains(lines[0], "猫") || strings.Contains(lines[0], "configured-old") {
		t.Fatalf("initial capture=%q", lines)
	}
	req.Config = map[string]string{"K": "configured-new"}
	run() // rotation uses the third value; cached configuration stays safe
	if len(lines) != 1 || strings.Contains(lines[0], "configured-old") {
		t.Fatalf("rotation capture=%q", lines)
	}
	waitLog(t, &sink, "old")
	r.mu.Lock()
	p := r.procs["mixed"]
	r.mu.Unlock()
	req.Args = []any{"a", "新"}
	run() // fourth distinct value: mute all diagnostics and clear old credentials
	if len(lines) != 0 {
		t.Fatalf("capacity capture=%q", lines)
	}
	assertMasksCleared(t, p)
	for i := 0; i < 5; i++ {
		run()
		if len(lines) != 0 {
			t.Fatalf("resumed capture=%q", lines)
		}
	}
	r.logLine(p, []byte("configured-old 猫"))
	r.logLine(p, []byte(`{"conn":"unknown","level":"error","msg":"configured-old 猫"}`))
	if strings.Contains(sink.String(), "configured-old") || strings.Contains(sink.String(), "猫") {
		t.Fatalf("cached value leaked: %s", sink.String())
	}
	req.Source = `function login(e,p,cb){console.log(globalThis.old);cb(new ValidationError("code","business failure"));}`
	_, err := r.Execute(context.Background(), req)
	se := scriptErr(t, err, KindValidation)
	if se.Code != "code" || se.Message != "business failure" || len(lines) != 0 {
		t.Fatalf("error/capture changed: %+v %q", se, lines)
	}
}

func TestRunnerBoundedMasksDeadlineWhileLiveAndCanceled(t *testing.T) {
	var sink syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(&sink, nil)))
	clock := &maskTestClock{now: time.Unix(100, 0)}
	r.maskPolicy = clock.policy(256, 64<<10)
	req := Request{TenantID: "deadline", ConnectionID: "c", Script: "login", Args: []any{"a", "old-password"}, Source: `function login(e,p,cb){globalThis.old??=p;console.log(globalThis.old);if(e==="cancel"){setTimeout(()=>{console.log(globalThis.old);cb(null,{ok:true})},100)}else cb(null,{ok:true});}`}
	if _, err := r.Execute(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	waitLog(t, &sink, "custom database script")
	r.mu.Lock()
	p := r.procs["deadline"]
	r.mu.Unlock()
	// A canceled caller hands the still-running request to the pool watcher.
	ctx, cancel := context.WithCancel(context.Background())
	req.Args = []any{"cancel", "new-password"}
	finished := make(chan error, 1)
	go func() { _, err := r.Execute(ctx, req); finished <- err }()
	// Observe registration, rather than guessing when Node has started.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		registered := len(p.values) == 2
		p.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request not registered")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
	clock.advance(time.Minute)
	assertMasksCleared(t, p) // process remains live, independently of its watcher
	req.Args = []any{"a", "third-password"}
	var lines []string
	req.OnLogs = func(v []string) { lines = v }
	raw, err := r.Execute(context.Background(), req)
	if err != nil || string(raw) != `{"ok":true}` || len(lines) != 0 {
		t.Fatalf("after deadline raw=%s err=%v logs=%q", raw, err, lines)
	}
	// Flush late stderr and the cancellation watcher before checking its sink.
	time.Sleep(150 * time.Millisecond)
	if strings.Contains(sink.String(), "old-password") || strings.Contains(sink.String(), "new-password") {
		t.Fatalf("late output leaked: %s", sink.String())
	}
	r.mu.Lock()
	same := r.procs["deadline"] == p
	r.mu.Unlock()
	if !same {
		t.Fatal("test did not exercise a continuously live process")
	}
}

func TestProcessMasksUnknownConnectionUsesAllValues(t *testing.T) {
	p, _ := newMaskTestProcess(4, 100)
	p.registerMasks(logscrub.WithCredentials(context.Background(), "猫", "abc"), Request{ConnectionID: "first", Config: map[string]string{"K": "old-config"}})
	p.registerMasks(context.Background(), Request{ConnectionID: "second", Config: map[string]string{"K": "new-config"}})
	var sink syncBuffer
	r := &NodeRunner{log: slog.New(slog.NewJSONHandler(&sink, nil))}
	r.logLine(p, []byte(`{"conn":"unknown","level":"info","msg":"猫 abc old-config new-config"}`))
	r.logLine(p, []byte("猫 abc old-config new-config"))
	for _, secret := range []string{"猫", "abc", "old-config", "new-config"} {
		if strings.Contains(sink.String(), secret) {
			t.Fatalf("unknown/unstructured secret %q leaked: %s", secret, sink.String())
		}
	}
	if strings.Count(sink.String(), `"output":`) != 2 {
		t.Fatalf("active diagnostics missing: %s", sink.String())
	}
}

func TestProcessMasksOversizedRequestMetadataMutes(t *testing.T) {
	values := make([]string, 300)
	for i := range values {
		values[i] = fmt.Sprintf("metadata-%d", i)
	}
	p, _ := newMaskTestProcess(256, 64<<10)
	p.registerMasks(logscrub.WithCredentials(context.Background(), values...), Request{})
	assertMasksCleared(t, p)
	if got := p.capture([]string{"metadata-299"}); len(got) != 0 {
		t.Fatalf("oversized metadata capture=%q", got)
	}
}

func TestRunnerBoundedMasksQuietDeadlineActualTimer(t *testing.T) {
	r := newRunner(t, config.CustomDB{})
	r.maskPolicy = maskPolicy{retention: 20 * time.Millisecond}
	if _, err := execLogin(t, r, `function login(e,p,cb){cb(null,{ok:true})}`); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	p := r.procs["t1"]
	r.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.mu.Lock()
		muted := p.muted
		p.mu.Unlock()
		if muted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("quiet live process retained masks beyond timer")
		}
		time.Sleep(time.Millisecond)
	}
	assertMasksCleared(t, p)
	r.mu.Lock()
	same := r.procs["t1"] == p
	r.mu.Unlock()
	if !same {
		t.Fatal("process retired before deadline test")
	}
}

type maskBlockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *maskBlockingWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(b), nil
}

func TestRunnerBoundedMasksBlockedLoggerDoesNotDelayExpiryOrBusiness(t *testing.T) {
	writer := &maskBlockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	r := newRunnerLog(t, config.CustomDB{}, slog.New(slog.NewJSONHandler(writer, nil)))
	clock := &maskTestClock{now: time.Unix(100, 0)}
	r.maskPolicy = clock.policy(256, 64<<10)
	req := Request{TenantID: "blocked", ConnectionID: "c", Script: "login", Source: `function login(e,p,cb){console.log(p);cb(null,{ok:true});}`, Args: []any{"a", "blocking-secret"}}
	first := make(chan error, 1)
	go func() { _, err := r.Execute(context.Background(), req); first <- err }()
	select {
	case <-writer.entered:
	case <-time.After(5 * time.Second):
		close(writer.release)
		t.Fatal("stderr did not enter handler")
	}
	expired := make(chan struct{})
	go func() { clock.advance(time.Minute); close(expired) }()
	defer close(writer.release)
	select {
	case <-expired:
	case <-time.After(time.Second):
		t.Fatal("slow stderr handler blocked physical mask clearing")
	}
	r.mu.Lock()
	p := r.procs["blocked"]
	r.mu.Unlock()
	assertMasksCleared(t, p)
	second := make(chan error, 1)
	go func() {
		raw, err := r.Execute(context.Background(), req)
		if err == nil && string(raw) != `{"ok":true}` {
			err = fmt.Errorf("raw=%s", raw)
		}
		second <- err
	}()
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow stderr handler blocked business call")
	}
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow stderr handler blocked first response")
	}
}
