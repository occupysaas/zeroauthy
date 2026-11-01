package logstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type sinkFunc func(context.Context, *store.LogStream, map[string]any, []Item) error

func (f sinkFunc) Send(c context.Context, s *store.LogStream, k map[string]any, i []Item) error {
	return f(c, s, k, i)
}
func fixture(t *testing.T) (*memory.Store, *store.LogStream, *Worker, *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	db := memory.NewWithClock(func() time.Time { return now.Add(-3 * time.Second) })
	s := &store.LogStream{TenantID: "t", ID: "s", Type: "http", Status: "active", Sink: map[string]any{"httpEndpoint": "https://example.com"}}
	if err := db.Logs().CreateLogStream(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	w := NewWorker(db, nil, logs.Config{Now: func() time.Time { return now }}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return db, stream(t, db), w, &now
}
func appendEvents(t *testing.T, db *memory.Store, now time.Time, types ...string) {
	t.Helper()
	for _, typ := range types {
		if err := db.Logs().AppendLogs(context.Background(), []store.LogEvent{{TenantID: "t", Type: typ, Date: now, Body: []byte(`{"type":"` + typ + `","email":"alice@example.com","details":{"email":"alice@example.com","password":"NEVER_OUT"}}`)}}, nil); err != nil {
			t.Fatal(err)
		}
	}
}
func stream(t *testing.T, db *memory.Store) *store.LogStream {
	t.Helper()
	s, e := db.Logs().GetLogStream(context.Background(), "t", "s")
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func TestDeliveryFiltersAndPII(t *testing.T) {
	for _, method := range []string{"mask", "hash"} {
		t.Run(method, func(t *testing.T) {
			db, s, w, now := fixture(t)
			s.Filters = []store.LogStreamFilter{{Type: "category", Name: "auth.login.success"}}
			s.PII = &store.LogStreamPII{LogFields: []string{"email"}, Method: method, Algorithm: "xxhash"}
			s.StartFrom = now.Add(-time.Hour)
			if err := db.Logs().UpdateLogStream(context.Background(), s, s.Version); err != nil {
				t.Fatal(err)
			}
			appendEvents(t, db, *now, "f", "s")
			w.sink = sinkFunc(func(_ context.Context, _ *store.LogStream, _ map[string]any, items []Item) error {
				if len(items) != 1 || items[0].LogID != store.FormatLogID(2) {
					t.Fatalf("items %+v", items)
				}
				want := "[REDACTED]"
				if method == "hash" {
					want = hashPII("alice@example.com")
				}
				if bytes.Contains(items[0].Data, []byte("alice@example.com")) || bytes.Contains(items[0].Data, []byte("NEVER_OUT")) || bytes.Count(items[0].Data, []byte(want)) < 2 {
					t.Fatal(string(items[0].Data))
				}
				return nil
			})
			w.runOne(context.Background())
			if got := stream(t, db); got.Checkpoint != 2 {
				t.Fatal(got)
			}
			original, err := db.Logs().GetLog(context.Background(), "t", store.FormatLogID(2))
			if err != nil || !bytes.Contains(original.Body, []byte("alice@example.com")) {
				t.Fatal(original, err)
			}
			// A completely filtered next batch advances without a network send.
			appendEvents(t, db, *now, "f")
			*now = now.Add(2 * time.Second)
			w.sink = sinkFunc(func(context.Context, *store.LogStream, map[string]any, []Item) error {
				t.Fatal("filtered batch sent")
				return nil
			})
			w.runOne(context.Background())
			if stream(t, db).Checkpoint != 3 {
				t.Fatal("skip stalled")
			}
		})
	}
}

type recordHook struct {
	store.Logs
	before func() error
}

func (r recordHook) RecordDelivery(c context.Context, t, id, o string, d store.LogStreamDelivery) error {
	if r.before != nil {
		if e := r.before(); e != nil {
			return e
		}
	}
	return r.Logs.RecordDelivery(c, t, id, o, d)
}

type hookedStore struct {
	store.Store
	repo store.Logs
}

func (s hookedStore) Logs() store.Logs { return s.repo }
func TestDeliveryRestartNoLoss(t *testing.T) {
	db, _, w, now := fixture(t)
	appendEvents(t, db, *now, "s")
	var deliveries []string
	send := sinkFunc(func(_ context.Context, _ *store.LogStream, _ map[string]any, items []Item) error {
		deliveries = append(deliveries, items[0].LogID)
		return nil
	})
	w.sink = send
	w.st = hookedStore{db, recordHook{db.Logs(), func() error { return context.Canceled }}}
	w.runOne(context.Background())
	if stream(t, db).Checkpoint != 0 {
		t.Fatal("checkpoint survived crash")
	}
	*now = now.Add(61 * time.Second)
	fresh := NewWorker(db, nil, logs.Config{Now: func() time.Time { return *now }}, nil, nil)
	fresh.sink = send
	fresh.runOne(context.Background())
	if stream(t, db).Checkpoint != 1 || len(deliveries) != 2 || deliveries[0] != deliveries[1] {
		t.Fatal(deliveries)
	}
}
func TestDeliveryLeaseRace(t *testing.T) {
	db, _, w, now := fixture(t)
	appendEvents(t, db, *now, "s")
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	w.sink = sinkFunc(func(context.Context, *store.LogStream, map[string]any, []Item) error {
		calls.Add(1)
		close(entered)
		<-release
		return nil
	})
	other := NewWorker(db, nil, logs.Config{Now: func() time.Time { return *now }}, nil, nil)
	other.sink = w.sink
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); w.runOne(context.Background()) }()
	<-entered
	other.runOne(context.Background())
	close(release)
	wg.Wait()
	if calls.Load() != 1 || stream(t, db).Checkpoint != 1 {
		t.Fatal("duplicate lease")
	}
}
func TestDeliverySuspendsAfter24h(t *testing.T) {
	db, _, w, now := fixture(t)
	appendEvents(t, db, *now, "s")
	w.sink = sinkFunc(func(context.Context, *store.LogStream, map[string]any, []Item) error {
		return deliveryError("http_5xx")
	})
	w.runOne(context.Background())
	s := stream(t, db)
	if s.Failures != 1 || s.FailingSince.IsZero() || s.NextAt.Sub(*now) != time.Second || s.Checkpoint != 0 {
		t.Fatal(s)
	}
	*now = now.Add(24 * time.Hour)
	w.runOne(context.Background())
	s = stream(t, db)
	if s.Status != "suspended" || s.LastErrorClass != "http_5xx" || s.Checkpoint != 0 {
		t.Fatal(s)
	}
	if w.runOne(context.Background()) {
		t.Fatal("suspended leased")
	}
}
func TestResumeFromCheckpoint(t *testing.T) {
	db, s, w, now := fixture(t)
	appendEvents(t, db, now.Add(-48*time.Hour), "s", "s")
	s.Status = "paused"
	if e := db.Logs().UpdateLogStream(context.Background(), s, s.Version); e != nil {
		t.Fatal(e)
	}
	if _, e := db.Logs().PurgeLogs(context.Background(), now.Add(-24*time.Hour), 100); e != nil {
		t.Fatal(e)
	}
	s = stream(t, db)
	s.Status = "active"
	if e := db.Logs().UpdateLogStream(context.Background(), s, s.Version); e != nil {
		t.Fatal(e)
	}
	appendEvents(t, db, *now, "s")
	w.sink = sinkFunc(func(_ context.Context, _ *store.LogStream, _ map[string]any, i []Item) error {
		if len(i) != 1 || i[0].LogID != store.FormatLogID(3) {
			t.Fatal(i)
		}
		return nil
	})
	w.runOne(context.Background())
	if stream(t, db).Checkpoint != 3 {
		t.Fatal("resume skipped retained event")
	}
}
func TestStartFromAndLeaseFencing(t *testing.T) {
	db, s, w, now := fixture(t)
	s.StartFrom = *now // create-only: recreate so date filter is retained.
	db.Logs().DeleteLogStream(context.Background(), "t", "s")
	if e := db.Logs().CreateLogStream(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	appendEvents(t, db, now.Add(-time.Hour), "s")
	appendEvents(t, db, *now, "s")
	var owner string
	w.sink = sinkFunc(func(_ context.Context, leased *store.LogStream, _ map[string]any, i []Item) error {
		owner = leased.LeaseOwner
		if len(i) != 1 || i[0].LogID != store.FormatLogID(2) {
			t.Fatal(i)
		}
		updated := stream(t, db)
		updated.Status = "paused"
		return db.Logs().UpdateLogStream(context.Background(), updated, updated.Version)
	})
	w.runOne(context.Background())
	if stream(t, db).Checkpoint != 0 {
		t.Fatal("stale lease checkpoint")
	}
	s = stream(t, db)
	s.Status = "active"
	db.Logs().UpdateLogStream(context.Background(), s, s.Version)
	w.sink = sinkFunc(func(_ context.Context, s *store.LogStream, _ map[string]any, _ []Item) error {
		if s.LeaseOwner == owner {
			t.Fatal("acquisition reused owner")
		}
		return nil
	})
	w.runOne(context.Background())
	if stream(t, db).Checkpoint != 2 {
		t.Fatal("resume")
	}
}
func TestHTTPSinkFormats(t *testing.T) {
	for _, format := range []string{"JSONARRAY", "JSONLINES", "JSONOBJECT"} {
		t.Run(format, func(t *testing.T) {
			var bodies []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("X-Test") != "value" || r.Header.Get("Content-Type") != "custom/json" {
					t.Error(r.Header)
				}
				b, _ := io.ReadAll(r.Body)
				bodies = append(bodies, string(b))
				w.WriteHeader(204)
			}))
			defer server.Close()
			sink := newHTTPSink(logs.StreamsConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true}, nil)
			s := &store.LogStream{Type: "http", Sink: map[string]any{"httpEndpoint": server.URL, "httpContentFormat": format, "httpContentType": "custom/json"}}
			items := []Item{{LogID: "1", Data: json.RawMessage(`{"email":"ok","password":"secret"}`)}, {LogID: "2", Data: json.RawMessage(`{"type":"s"}`)}}
			if e := sink.Send(context.Background(), s, map[string]any{"httpAuthorization": "Bearer secret", "httpCustomHeaders": []any{map[string]any{"header": "X-Test", "value": "value"}}}, items); e != nil {
				t.Fatal(e)
			}
			count := 1
			if format == "JSONOBJECT" {
				count = 2
			}
			if len(bodies) != count {
				t.Fatal(bodies)
			}
			for _, b := range bodies {
				if strings.Contains(b, `"password":"secret"`) {
					t.Fatal("sink missing final scrub")
				}
			}
			if format == "JSONARRAY" {
				var rows []Item
				if json.Unmarshal([]byte(bodies[0]), &rows) != nil || len(rows) != 2 {
					t.Fatal(bodies)
				}
			}
			if format == "JSONLINES" && (strings.Count(bodies[0], "\n") != 2 || !strings.HasSuffix(bodies[0], "\n")) {
				t.Fatal(bodies)
			}
		})
	}
}
func TestInsecureHTTPRefusedByDefault(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	s := &store.LogStream{Type: "http", Sink: map[string]any{"httpEndpoint": server.URL}}
	e := newHTTPSink(logs.StreamsConfig{}, nil).Send(context.Background(), s, nil, []Item{{LogID: "1", Data: json.RawMessage(`{}`)}})
	if e == nil || calls.Load() != 0 {
		t.Fatal(e, calls.Load())
	}
}
func TestXXHash64Vectors(t *testing.T) {
	for input, want := range map[string]string{"": "ef46db3751d8e999", "a": "d24ec4f1a98c6e5b", "abc": "44bc2cf5ad770999", "message digest": "066ed728fceeb3be", "abcdefghijklmnopqrstuvwxyz": "cfe1f278fa89835c", "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e04a477f19ee145d"} {
		if got := hashPII(input); got != want {
			t.Fatalf("%q: %s != %s", input, got, want)
		}
	}
}

type unavailableProbe struct {
	store.Logs
	called chan struct{}
}

func (p unavailableProbe) LeaseLogStream(context.Context, string, time.Time, time.Time) (*store.LogStream, error) {
	select {
	case p.called <- struct{}{}:
	default:
	}
	return nil, store.ErrLogsUnavailable
}
func TestWorkerUnavailableAndCancellation(t *testing.T) {
	db, _, w, _ := fixture(t)
	attempted := make(chan struct{}, 1)
	w.st = hookedStore{db, unavailableProbe{Logs: store.UnimplementedLogs{}, called: attempted}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	select {
	case <-attempted:
	case <-time.After(time.Second):
		t.Fatal("unavailable repository not attempted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker ignored shutdown")
	}
	// Capability negotiation may recover later; each idle attempt consults the
	// current repository, rather than permanently disabling delivery at startup.
	w.st = db
	if !w.runOne(context.Background()) {
		t.Fatal("worker did not retry after capability recovery")
	}
}

func TestExpiredAcquisitionCannotCheckpoint(t *testing.T) {
	db, _, w, now := fixture(t)
	appendEvents(t, db, *now, "s")
	other := NewWorker(db, nil, logs.Config{Now: func() time.Time { return *now }}, nil, nil)
	var oldOwner string
	other.sink = sinkFunc(func(_ context.Context, s *store.LogStream, _ map[string]any, _ []Item) error {
		if s.LeaseOwner == oldOwner {
			t.Fatal("owner reused")
		}
		return nil
	})
	w.sink = sinkFunc(func(_ context.Context, s *store.LogStream, _ map[string]any, _ []Item) error {
		oldOwner = s.LeaseOwner
		*now = now.Add(64 * time.Second)
		other.runOne(context.Background())
		return deliveryError("http_5xx")
	})
	w.runOne(context.Background())
	s := stream(t, db)
	if s.Checkpoint != 1 || s.Failures != 0 || s.LastErrorClass != "" {
		t.Fatal("stale acquisition overwrote delivery", s)
	}
}
func TestWorkerBackoffAndReset(t *testing.T) {
	db, _, w, now := fixture(t)
	appendEvents(t, db, *now, "s")
	w.sink = sinkFunc(func(context.Context, *store.LogStream, map[string]any, []Item) error {
		return deliveryError("http_4xx")
	})
	for i := 0; i < 12; i++ {
		w.runOne(context.Background())
		s := stream(t, db)
		want := time.Second << i
		if want > 5*time.Minute {
			want = 5 * time.Minute
		}
		if s.NextAt.Sub(*now) != want || s.Failures != i+1 || s.Checkpoint != 0 {
			t.Fatal(i, s)
		}
		*now = s.NextAt
	}
	w.sink = sinkFunc(func(context.Context, *store.LogStream, map[string]any, []Item) error { return nil })
	w.runOne(context.Background())
	s := stream(t, db)
	if s.Failures != 0 || !s.FailingSince.IsZero() || s.LastErrorClass != "" || s.LastSuccessAt.IsZero() || s.Checkpoint != 1 {
		t.Fatal(s)
	}
}
func TestWorkerSealedSecretsAndSettledBatch(t *testing.T) {
	db, s, w, now := fixture(t)
	wrapper, err := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	w.keys = wrapper
	s.SealedSecrets, err = SealSecrets(wrapper, s, map[string]any{"httpAuthorization": "SENTINEL_AUTH"})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Logs().UpdateLogStream(context.Background(), s, s.Version); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, db, *now, "s")
	var called bool
	w.st = hookedStore{db, readHook{Logs: db.Logs(), check: func(after int64, q *store.LogQuery, take int, settled time.Time) {
		if after != 0 || q != nil || take != 100 || !settled.Equal(now.Add(-2*time.Second)) {
			t.Fatal(after, q, take, settled)
		}
	}}}
	w.sink = sinkFunc(func(c context.Context, s *store.LogStream, private map[string]any, i []Item) error {
		called = true
		if private["httpAuthorization"] != "SENTINEL_AUTH" {
			t.Fatal("secret missing")
		}
		deadline, ok := c.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Fatal("missing timeout")
		}
		if bytes.Contains(i[0].Data, []byte("SENTINEL_AUTH")) {
			t.Fatal("secrets appended to payload")
		}
		return nil
	})
	w.runOne(context.Background())
	if !called || stream(t, db).Checkpoint != 1 {
		t.Fatal("no delivery")
	}
}

type readHook struct {
	store.Logs
	check func(int64, *store.LogQuery, int, time.Time)
}

func (r readHook) LogsAfter(c context.Context, tid string, after int64, q *store.LogQuery, take int, settled time.Time) ([]store.LogEvent, error) {
	r.check(after, q, take, settled)
	return r.Logs.LogsAfter(c, tid, after, q, take, settled)
}

func TestHTTPSinkShortCredentialPreservesSchema(t *testing.T) {
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- b
		w.WriteHeader(204)
	}))
	defer server.Close()
	sink := newHTTPSink(logs.StreamsConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true}, nil)
	stream := &store.LogStream{Type: "http", Sink: map[string]any{"httpEndpoint": server.URL, "httpContentFormat": "JSONARRAY", "httpContentType": "application/json"}}
	body := json.RawMessage(`{"date":"2026-10-30T12:00:00Z","type":"s","log_id":"00000000000000000000000000000000000000000000000000000001","details":{"actions":{"executions":["exe_abcdefghijklmnopqrstuvwx"]},"echo-e":"e"}}`)
	if err := sink.Send(context.Background(), stream, map[string]any{"httpAuthorization": "e"}, []Item{{LogID: "1", Data: body}}); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(<-received, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal(got)
	}
	data := got[0]["data"].(map[string]any)
	if data["date"] != "2026-10-30T12:00:00Z" || data["type"] != "s" || data["log_id"] != "00000000000000000000000000000000000000000000000000000001" {
		t.Fatal(got)
	}
	details := data["details"].(map[string]any)
	if details["actions"].(map[string]any)["executions"].([]any)[0] != "exe_abcdefghijklmnopqrstuvwx" || details["[REDACTED]cho-[REDACTED]"] != "[REDACTED]" {
		t.Fatal(details)
	}
}
