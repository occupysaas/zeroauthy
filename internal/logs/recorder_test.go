package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var bg = context.Background()

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func tenantStore(t *testing.T) *memory.Store {
	t.Helper()
	st := memory.New()
	if err := st.Tenants().Create(bg, &store.Tenant{ID: "t", Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	return st
}

type wrappedStore struct {
	store.Store
	repo    store.Logs
	tenants store.Tenants
}

func (s wrappedStore) Logs() store.Logs { return s.repo }
func (s wrappedStore) Tenants() store.Tenants {
	if s.tenants != nil {
		return s.tenants
	}
	return s.Store.Tenants()
}

type blockedLogs struct {
	store.Logs
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	err     error
}

func (s *blockedLogs) AppendLogs(ctx context.Context, e []store.LogEvent, d []store.DailyStatDelta) error {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if s.err != nil {
		return s.err
	}
	return s.Logs.AppendLogs(ctx, e, d)
}

type countingTenants struct {
	store.Tenants
	count atomic.Int64
}

func (s *countingTenants) Get(ctx context.Context, id string) (*store.Tenant, error) {
	s.count.Add(1)
	return s.Tenants.Get(ctx, id)
}

type safeBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) { s.Lock(); defer s.Unlock(); return s.b.Write(p) }
func (s *safeBuffer) String() string              { s.Lock(); defer s.Unlock(); return s.b.String() }
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	limit := time.Now().Add(2 * time.Second)
	for !fn() {
		if time.Now().After(limit) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestRecorderNeverBlocks(t *testing.T) {
	st := tenantStore(t)
	block := &blockedLogs{Logs: st.Logs(), entered: make(chan struct{}), release: make(chan struct{})}
	var ns atomic.Int64
	ns.Store(time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC).UnixNano())
	out := &safeBuffer{}
	r := NewRecorder(wrappedStore{Store: st, repo: block}, Config{QueueSize: 100, Now: func() time.Time { return time.Unix(0, ns.Load()) }}, slog.New(slog.NewTextHandler(out, nil)))
	go r.Run(bg)
	for range 100 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	<-block.entered
	start := time.Now()
	for range 1000 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("1000 Record calls took %s", elapsed)
	}
	if r.Dropped() == 0 {
		t.Fatal("full queue did not count drops")
	}
	eventually(t, func() bool { return strings.Count(out.String(), "log events dropped") == 1 })
	close(block.release)
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "log events dropped") != 1 {
		t.Fatalf("warning count: %s", out.String())
	}
}
func TestRecorderDropWarningRate(t *testing.T) {
	st := tenantStore(t)
	var ns atomic.Int64
	ns.Store(time.Now().UnixNano())
	out := &safeBuffer{}
	r := NewRecorder(st, Config{QueueSize: 1, Now: func() time.Time { return time.Unix(0, ns.Load()) }}, slog.New(slog.NewTextHandler(out, nil)))
	// Queue pressure before Run must not block or synchronously use the logger.
	for range 3 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	go r.Run(bg)
	eventually(t, func() bool { return strings.Count(out.String(), "log events dropped") == 1 })
	for range 1000 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	ns.Add(int64(time.Minute))
	for range 1000 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	eventually(t, func() bool { return strings.Count(out.String(), "log events dropped") == 2 })
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
}
func TestRecorderScrubsBeforeStore(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	ctx := logscrub.WithValues(bg, "hunter2-secret", "dynamic-secret")
	details := map[string]any{"deep": []any{map[string]any{"password": "hidden-value", "dynamic-secret": "dynamic-secret", "body": `{"note":"hunter2-secret","password":"encoded-value"}`}}}
	r.Record(ctx, Event{TenantID: "t", Type: "s", Description: "hello hunter2-secret", UserName: "hunter2-secret", Details: details, ExecutionIDs: []string{"exec1"}})
	details["late"] = "must not appear"
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v %v", rows, err)
	}
	body := string(rows[0].Body)
	for _, secret := range []string{"hunter2-secret", "dynamic-secret", "hidden-value", "encoded-value", "must not appear"} {
		if strings.Contains(body, secret) {
			t.Fatalf("leaked %s: %s", secret, body)
		}
	}
	var obj map[string]any
	json.Unmarshal(rows[0].Body, &obj)
	if obj["tenant_name"] != "acme" || obj["client_id"] != nil || obj["date"] == nil {
		t.Fatalf("body: %s", body)
	}
	if !strings.Contains(body, `"executions":["exec1"]`) {
		t.Fatalf("executions missing: %s", body)
	}
}
func TestRecorderStats(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	date := time.Date(2026, 10, 30, 23, 0, 0, 0, time.FixedZone("west", -3*3600))
	for _, typ := range []string{"s", "ss", "pwd_leak", "f"} {
		r.Record(logscrub.WithValues(bg, "leak"), Event{TenantID: "t", Type: typ, Date: date})
	}
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100})
	if err != nil || len(rows) != 4 {
		t.Fatalf("stats events %d err %v", len(rows), err)
	}
	maskedType := false
	for _, row := range rows {
		if strings.Contains(string(row.Body), "leak") || strings.Contains(row.Type, "leak") {
			t.Fatalf("stats event leaked mask: %s (%s)", row.Body, row.Type)
		}
		if row.Type == "pwd_"+logscrub.Marker {
			maskedType = true
		}
	}
	if !maskedType {
		t.Fatal("leaked-password display type was not masked")
	}
	day := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	stats, err := st.Logs().DailyStats(bg, "t", day, day)
	if err != nil || len(stats) != 1 || stats[0].Logins != 1 || stats[0].Signups != 1 || stats[0].LeakedPasswords != 1 {
		t.Fatalf("stats %+v err %v", stats, err)
	}
}
func TestRecorderFlushOnShutdown(t *testing.T) {
	st := tenantStore(t)
	tenants := &countingTenants{Tenants: st.Tenants()}
	r := NewRecorder(wrappedStore{Store: st, repo: st.Logs(), tenants: tenants}, Config{}, quiet())
	for range 205 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	rows, total, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if err != nil || len(rows) != 100 || total != 205 {
		t.Fatalf("rows %d total %d err %v", len(rows), total, err)
	}
	if tenants.count.Load() != 3 {
		t.Fatalf("tenant lookups %d, want 3 batches", tenants.count.Load())
	}
	r.Record(bg, Event{TenantID: "t", Type: "s"})
	if r.Dropped() != 1 {
		t.Fatal("record after shutdown not dropped")
	}
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
}
func TestRecorderFlushWaitsForInflightAndReportsError(t *testing.T) {
	st := tenantStore(t)
	boom := errors.New("offline")
	block := &blockedLogs{Logs: st.Logs(), entered: make(chan struct{}), release: make(chan struct{}), err: boom}
	r := NewRecorder(wrappedStore{Store: st, repo: block}, Config{}, quiet())
	for range 100 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	go r.Run(bg)
	<-block.entered
	done := make(chan error, 1)
	go func() { done <- r.Flush(bg) }()
	select {
	case <-done:
		t.Fatal("flush returned during append")
	case <-time.After(15 * time.Millisecond):
	}
	close(block.release)
	if err := <-done; !errors.Is(err, boom) {
		t.Fatalf("flush error %v", err)
	}
	if r.Dropped() != 100 {
		t.Fatalf("dropped %d", r.Dropped())
	}
	stats, _ := st.Logs().DailyStats(bg, "t", time.Time{}, time.Now().Add(time.Hour))
	if len(stats) != 0 {
		t.Fatal("failed batch committed stats")
	}
}
func TestRecorderFlushDeadline(t *testing.T) {
	st := tenantStore(t)
	block := &blockedLogs{Logs: st.Logs(), entered: make(chan struct{}), release: make(chan struct{})}
	r := NewRecorder(wrappedStore{Store: st, repo: block}, Config{}, quiet())
	r.Record(bg, Event{TenantID: "t", Type: "s"})
	ctx, cancel := context.WithTimeout(bg, 25*time.Millisecond)
	defer cancel()
	if err := r.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush %v", err)
	}
	eventually(t, func() bool { return r.Dropped() == 1 })
}
func TestRecorderConcurrentFlush(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	go r.Run(bg)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				r.Record(bg, Event{TenantID: "t", Type: "s"})
			}
		})
	}
	wg.Wait()
	for range 8 {
		wg.Go(func() {
			if err := r.Flush(bg); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	_, total, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if err != nil || total != 800 {
		t.Fatalf("total %d err %v", total, err)
	}
}
func TestFromRequestAndIDs(t *testing.T) {
	req := httptest.NewRequest("GET", "https://acme.test/", nil)
	req.RemoteAddr = "192.0.2.3:1234"
	req.Header.Set("User-Agent", "agent")
	req = req.WithContext(tenant.WithResolved(bg, tenant.Resolved{Tenant: &store.Tenant{ID: "t"}, Host: "acme.test"}))
	e := FromRequest(req)
	if e.TenantID != "t" || e.IP != "192.0.2.3" || e.Hostname != "acme.test" || e.UserAgent != "agent" {
		t.Fatalf("event %+v", e)
	}
	if id := FormatID(42); len(id) != 56 {
		t.Fatal(id)
	} else if n, ok := ParseID(id); !ok || n != 42 {
		t.Fatal(n, ok)
	}
	if _, ok := ParseID("42"); ok {
		t.Fatal("accepted malformed ID")
	}
	Nop.Record(bg, e)
}

type observedLogs struct {
	store.Logs
	batches chan int
}

func (s *observedLogs) AppendLogs(ctx context.Context, e []store.LogEvent, d []store.DailyStatDelta) error {
	s.batches <- len(e)
	return s.Logs.AppendLogs(ctx, e, d)
}
func TestRecorderBatchSizeAndDelay(t *testing.T) {
	st := tenantStore(t)
	observed := &observedLogs{Logs: st.Logs(), batches: make(chan int, 10)}
	r := NewRecorder(wrappedStore{Store: st, repo: observed}, Config{}, quiet())
	go r.Run(bg)
	for range 100 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	select {
	case n := <-observed.batches:
		if n != 100 {
			t.Fatalf("full batch %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("full batch was not written")
	}
	r.Record(bg, Event{TenantID: "t", Type: "ss"})
	select {
	case n := <-observed.batches:
		if n != 1 {
			t.Fatalf("timed batch %d", n)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("partial batch did not flush in 250ms")
	}
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
}

type blockedTenants struct {
	store.Tenants
	entered chan struct{}
	release chan struct{}
}

func (s *blockedTenants) Get(ctx context.Context, id string) (*store.Tenant, error) {
	close(s.entered)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.release:
		return s.Tenants.Get(ctx, id)
	}
}
func TestRecorderNeverWaitsForTenantLookup(t *testing.T) {
	st := tenantStore(t)
	tenants := &blockedTenants{Tenants: st.Tenants(), entered: make(chan struct{}), release: make(chan struct{})}
	r := NewRecorder(wrappedStore{Store: st, repo: st.Logs(), tenants: tenants}, Config{QueueSize: 1100}, quiet())
	for range 100 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	go r.Run(bg)
	<-tenants.entered
	done := make(chan struct{})
	go func() {
		for range 1000 {
			r.Record(bg, Event{TenantID: "t", Type: "s"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Record waited for tenant lookup")
	}
	ctx, cancel := context.WithTimeout(bg, 10*time.Millisecond)
	defer cancel()
	if err := r.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush %v", err)
	}
}
func TestRecorderConcurrentRecordAndFlush(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	go r.Run(bg)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				r.Record(bg, Event{TenantID: "t", Type: "s"})
			}
		})
	}
	wg.Go(func() {
		if err := r.Flush(bg); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
	_, total, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if err != nil || uint64(total)+r.Dropped() != 800 {
		t.Fatalf("persisted %d dropped %d err %v", total, r.Dropped(), err)
	}
}

type recoveringStore struct {
	wrappedStore
	probes atomic.Int64
}

func (s *recoveringStore) CheckLogsSupport(context.Context) error {
	if s.probes.Add(1) == 1 {
		return errors.New("temporary probe failure")
	}
	return nil
}
func (s *recoveringStore) LogsSupported() bool { return s.probes.Load() > 1 }
func TestRecorderTransientCapabilityRecoverySameWriter(t *testing.T) {
	st := tenantStore(t)
	probe := &recoveringStore{wrappedStore: wrappedStore{Store: st, repo: st.Logs()}}
	r := NewRecorder(probe, Config{}, quiet())
	for range 200 {
		r.Record(bg, Event{TenantID: "t", Type: "s"})
	}
	if err := r.Flush(bg); err == nil {
		t.Fatal("Flush did not report failed first batch")
	}
	_, total, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100, IncludeTotals: true})
	if err != nil || total != 100 || r.Dropped() != 100 {
		t.Fatalf("recovered rows %d drops %d err %v", total, r.Dropped(), err)
	}
	stats, err := st.Logs().DailyStats(bg, "t", time.Time{}, time.Now().Add(time.Hour))
	if err != nil || len(stats) != 1 || stats[0].Logins != 100 {
		t.Fatalf("recovered stats %+v err %v", stats, err)
	}
}

func TestRecorderScrubsExecutionEnrichment(t *testing.T) {
	st := tenantStore(t)
	r := NewRecorder(st, Config{}, quiet())
	details := map[string]any{"actions": map[string]any{"existing": "keep"}}
	r.Record(logscrub.WithValues(bg, "actions", "executionsecret"), Event{TenantID: "t", Type: "s", Details: details, ExecutionIDs: []string{"executionsecret"}})
	if err := r.Flush(bg); err != nil {
		t.Fatal(err)
	}
	rows, _, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %v err %v", rows, err)
	}
	if body := string(rows[0].Body); strings.Contains(body, "actions") || strings.Contains(body, "executionsecret") {
		t.Fatalf("execution enrichment bypassed masks: %s", body)
	}
	if _, ok := details["actions"].(map[string]any)["executions"]; ok {
		t.Fatal("enrichment mutated caller details")
	}
}

type requestContextProbe struct {
	context.Context
	finished  atomic.Bool
	lateReads atomic.Int64
}

func (p *requestContextProbe) Value(key any) any {
	if p.finished.Load() {
		p.lateReads.Add(1)
	}
	return p.Context.Value(key)
}

func TestRecorderScrubsAsyncTenantName(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "stored", true: "fallback"}[fallback], func(t *testing.T) {
			st := tenantStore(t)
			tenants := &countingTenants{Tenants: st.Tenants()}
			output := &safeBuffer{}
			wrapped := wrappedStore{Store: st, repo: st.Logs(), tenants: tenants}
			var target store.Store = wrapped
			if fallback {
				target = &capabilityStore{wrappedStore: wrapped, err: store.ErrLogsUnavailable}
			}
			r := NewRecorder(target, Config{}, slog.New(slog.NewJSONHandler(output, nil)))
			ctx := &requestContextProbe{Context: logscrub.WithValues(bg, "acme")}
			r.Record(ctx, Event{TenantID: "t", Type: "f"})
			ctx.finished.Store(true)
			// A second event shares the batch tenant lookup, but has a different mask.
			r.Record(bg, Event{TenantID: "t", Type: "s"})
			if err := r.Flush(bg); err != nil {
				t.Fatal(err)
			}
			if ctx.lateReads.Load() != 0 {
				t.Fatalf("writer read request context %d times", ctx.lateReads.Load())
			}
			if tenants.count.Load() != 1 {
				t.Fatalf("tenant lookups %d, want 1 per batch", tenants.count.Load())
			}
			bodies := map[string]map[string]any{}
			if fallback {
				for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
					var entry struct {
						Event map[string]any `json:"event"`
					}
					if err := json.Unmarshal([]byte(line), &entry); err != nil {
						t.Fatal(err)
					}
					typ, _ := entry.Event["type"].(string)
					bodies[typ] = entry.Event
				}
			} else {
				rows, _, err := st.Logs().SearchLogs(bg, "t", nil, store.LogPage{PerPage: 100})
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows {
					var body map[string]any
					if err := json.Unmarshal(row.Body, &body); err != nil {
						t.Fatal(err)
					}
					bodies[row.Type] = body
				}
			}
			if len(bodies) != 2 || bodies["f"]["tenant_name"] != logscrub.Marker || bodies["s"]["tenant_name"] != "acme" {
				t.Fatalf("async tenant masks %+v", bodies)
			}
		})
	}
}
