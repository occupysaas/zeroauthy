package eventstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"golang.org/x/net/dns/dnsmessage"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("response-must-never-be-stored")), Header: make(http.Header)}
}
func testWorker(t *testing.T, code int) (*Worker, store.Store, *store.EventStream) {
	t.Helper()
	st := memory.New()
	ctx := context.Background()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t", CanonicalHost: "t.example"}); err != nil {
		t.Fatal(err)
	}
	key, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &store.EventStream{TenantID: "t", ID: "s", Name: "s", Status: "enabled", DestType: "webhook", Subscriptions: []string{"user.created"}, Config: map[string]any{"webhook_endpoint": "https://receiver.example/hook?key=public", "webhook_authorization": map[string]any{"method": "bearer"}}}
	s.SealedSecret, err = SealSecrets(key, s, map[string]any{"token": "bearer-private-value"})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Events().CreateEventStream(ctx, s); err != nil {
		t.Fatal(err)
	}
	w := NewWorker(st, key, events.DefaultConfig(), &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(code), nil })}, nil, nil)
	// Real repository clocks remain behind the injected settled/read clock.
	at := time.Now().Add(time.Minute)
	w.now = func() time.Time { return at }
	w.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		at = at.Add(d)
		return nil
	}
	return w, st, s
}
func appendEvent(t *testing.T, st store.Store, id, typ string) {
	t.Helper()
	if err := st.Events().AppendEvents(context.Background(), []store.TenantEvent{{TenantID: "t", ID: id, Type: typ, Time: time.Now(), Body: []byte(`{"specversion":"1.0","id":"` + id + `","type":"` + typ + `","data":{"object":{"user_id":"u"}}}`)}}); err != nil {
		t.Fatal(err)
	}
}
func streamState(t *testing.T, st store.Store) *store.EventStream {
	t.Helper()
	s, err := st.Events().GetEventStream(context.Background(), "t", "s")
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func updateStream(t *testing.T, st store.Store, fn func(*store.EventStream)) {
	t.Helper()
	s := streamState(t, st)
	fn(s)
	if err := st.Events().UpdateEventStream(context.Background(), s, s.Version); err != nil {
		t.Fatal(err)
	}
}

// Catches missing authorization, incorrect content type and mutation of persisted bodies.
func TestWebhookAuthorization(t *testing.T) {
	for _, method := range []string{"basic", "bearer", "custom_header"} {
		t.Run(method, func(t *testing.T) {
			w, st, s := testWorker(t, 204)
			auth := map[string]any{"method": method}
			secret := map[string]any{}
			header, want := "Authorization", ""
			switch method {
			case "basic":
				auth["username"] = "alice"
				secret["password"] = "private-pass"
				want = "Basic YWxpY2U6cHJpdmF0ZS1wYXNz"
			case "bearer":
				secret["token"] = "private-token"
				want = "Bearer private-token"
			case "custom_header":
				auth["header_key"] = "X-Hook-Key"
				secret["header_value"] = "private-header"
				header = "X-Hook-Key"
				want = "private-header"
			}
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get(header) != want || r.URL.RawQuery != "key=public" {
					t.Errorf("incorrect webhook request: method=%s type=%s", r.Method, r.Header.Get("Content-Type"))
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["a0stream"] != "s" || body["id"] != "e" {
					t.Errorf("body=%v", body)
				}
				rw.WriteHeader(204)
			}))
			defer srv.Close()
			s.Config = map[string]any{"webhook_endpoint": srv.URL + "/hook?key=public", "webhook_authorization": auth}
			s.SealedSecret, _ = SealSecrets(w.keys, s, secret)
			if err := st.Events().UpdateEventStream(context.Background(), s, s.Version); err != nil {
				t.Fatal(err)
			}
			w = NewWorker(st, w.keys, events.Config{AllowPrivateNetworks: true, AllowInsecureHTTP: true}, nil, nil, nil)
			w.now = func() time.Time { return time.Now().Add(time.Minute) }
			appendEvent(t, st, "e", "user.created")
			if !w.runOne(context.Background()) {
				t.Fatal("no delivery")
			}
			if streamState(t, st).Checkpoint != 1 {
				t.Fatal("not recorded")
			}
			e, _ := st.Events().GetEvent(context.Background(), "t", "e")
			if strings.Contains(string(e.Body), "a0stream") {
				t.Fatal("persisted body mutated")
			}
		})
	}
}

func TestRetrySchedule(t *testing.T) {
	for _, tc := range []struct {
		name       string
		code, want int
		err        error
	}{{"500", 500, 4, nil}, {"404", 404, 1, nil}, {"204", 204, 1, nil}, {"timeout", 0, 4, context.DeadlineExceeded}} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, s := testWorker(t, tc.code)
			var starts []time.Duration
			var delays []time.Duration
			at := time.Now()
			base := at
			w.now = func() time.Time { return at }
			w.sleep = func(_ context.Context, d time.Duration) error { delays = append(delays, d); at = at.Add(d); return nil }
			w.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				starts = append(starts, at.Sub(base))
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > 10*time.Second {
					t.Error("attempt lacks 10s timeout")
				}
				if tc.err != nil {
					return nil, tc.err
				}
				return response(tc.code), nil
			})
			got := w.Deliver(context.Background(), s, []byte(`{}`))
			if len(got) != tc.want {
				t.Fatalf("attempts=%v", got)
			}
			if tc.want == 4 && (!reflect.DeepEqual(delays, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) || !reflect.DeepEqual(starts, []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second})) {
				t.Fatalf("delays=%v starts=%v", delays, starts)
			}
			if tc.err != nil && got[0].ErrorMessage != "timeout" {
				t.Fatal(got)
			}
		})
	}
}

func TestFailureRecordAndCounters(t *testing.T) {
	w, st, _ := testWorker(t, 500)
	appendEvent(t, st, "e", "user.created")
	if !w.runOne(context.Background()) {
		t.Fatal("idle")
	}
	s := streamState(t, st)
	d, err := st.Events().GetDelivery(context.Background(), "t", "s", "e")
	if err != nil || len(d.Attempts) != 4 || s.TotalFailures != 1 || s.ConsecutiveFailures != 1 || s.Checkpoint != 1 {
		t.Fatalf("state=%+v delivery=%+v err=%v", s, d, err)
	}
	if strings.Contains(fmt.Sprint(d), "response-must-never") || strings.Contains(fmt.Sprint(d), "bearer-private") {
		t.Fatal("secret response leaked")
	}
	if _, err = st.Events().QueueRedelivery(context.Background(), "t", "s", []string{"e"}, nil); err != nil {
		t.Fatal(err)
	}
	w.runOne(context.Background())
	if streamState(t, st).TotalFailures != 1 || streamState(t, st).ConsecutiveFailures != 2 {
		t.Fatal("redelivery counted twice")
	}
	_, err = st.Events().QueueRedelivery(context.Background(), "t", "s", []string{"e"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(204), nil })
	w.runOne(context.Background())
	s = streamState(t, st)
	if s.TotalFailures != 0 || s.ConsecutiveFailures != 0 {
		t.Fatalf("success counters=%+v", s)
	}
	if _, err = st.Events().GetDelivery(context.Background(), "t", "s", "e"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestAutoDisable500Consecutive(t *testing.T) {
	w, st, _ := testWorker(t, 404)
	for i := 0; i < 501; i++ {
		appendEvent(t, st, fmt.Sprintf("e%04d", i), "user.created")
	}
	for i := 0; i < 500; i++ {
		if !w.runOne(context.Background()) {
			t.Fatal(i)
		}
	}
	s := streamState(t, st)
	if s.Status != "disabled" || s.ConsecutiveFailures != 500 || s.Checkpoint != 500 {
		t.Fatalf("%+v", s)
	}
	w.runOne(context.Background())
	if streamState(t, st).Checkpoint != 500 {
		t.Fatal("disabled consumed new event")
	}
}

func TestAutoDisable5000Total(t *testing.T) {
	w, st, _ := testWorker(t, 404)
	ctx := context.Background()
	// Seed real extant failure records, resetting consecutive failures between them.
	for i := 0; i < 4999; i++ {
		id := fmt.Sprintf("old%04d", i)
		appendEvent(t, st, id, "user.created")
		s, err := st.Events().LeaseEventStream(ctx, w.owner, w.now(), w.now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		err = st.Events().RecordEventDelivery(ctx, "t", "s", w.owner, store.DeliveryOutcome{Checkpoint: int64(i + 1), TotalFailures: i + 1, Failed: &store.EventDelivery{TenantID: "t", StreamID: "s", EventID: id, EventType: "user.created", Status: "failed"}})
		if err != nil {
			t.Fatal(err)
		}
		_ = s
	}
	appendEvent(t, st, "last", "user.created")
	w.runOne(ctx)
	s := streamState(t, st)
	if s.TotalFailures != 5000 || s.Status != "disabled" || s.ConsecutiveFailures != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestSubscriptionFilter(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	appendEvent(t, st, "unmatched", "user.updated")
	appendEvent(t, st, "matched", "user.created")
	var ids []string
	w.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		ids = append(ids, body["id"].(string))
		return response(204), nil
	})
	w.runOne(context.Background())
	if !reflect.DeepEqual(ids, []string{"matched"}) || streamState(t, st).Checkpoint != 2 {
		t.Fatalf("ids=%v", ids)
	}
	appendEvent(t, st, "tail", "user.updated")
	w.runOne(context.Background())
	if streamState(t, st).Checkpoint != 3 || len(ids) != 1 {
		t.Fatal("unmatched tail wedged")
	}
}

func TestDisabledStreamSkipsNewEvents(t *testing.T) {
	w, st, _ := testWorker(t, 404)
	appendEvent(t, st, "failed", "user.created")
	w.runOne(context.Background())
	updateStream(t, st, func(s *store.EventStream) { s.Status = "disabled" })
	appendEvent(t, st, "new", "user.created")
	if w.runOne(context.Background()) {
		t.Fatal("disabled received new")
	}
	if _, err := st.Events().QueueRedelivery(context.Background(), "t", "s", []string{"failed"}, nil); err != nil {
		t.Fatal(err)
	}
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(204), nil })
	if !w.runOne(context.Background()) {
		t.Fatal("disabled cannot redeliver")
	}
	s := streamState(t, st)
	if s.Status != "disabled" || s.Checkpoint != 1 || s.TotalFailures != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestQueuedRedeliveriesFirst(t *testing.T) {
	w, st, _ := testWorker(t, 404)
	appendEvent(t, st, "old", "user.created")
	w.runOne(context.Background())
	appendEvent(t, st, "new", "user.created")
	st.Events().QueueRedelivery(context.Background(), "t", "s", []string{"old"}, nil)
	w.runOne(context.Background())
	if streamState(t, st).Checkpoint != 1 || streamState(t, st).TotalFailures != 1 {
		t.Fatal("new delivered before queue")
	}
}

func TestRestartRedelivers(t *testing.T) {
	w, st, s := testWorker(t, 204)
	appendEvent(t, st, "e", "user.created")
	ctx, cancel := context.WithCancel(context.Background())
	sent := 0
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { sent++; cancel(); return response(204), nil })
	w.runOne(ctx)
	if streamState(t, st).Checkpoint != 0 {
		t.Fatal("cancelled owner checkpointed")
	}
	updateStream(t, st, func(s *store.EventStream) { s.LeaseUntil = time.Now().Add(-time.Second) })
	next := NewWorker(st, w.keys, events.DefaultConfig(), &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { sent++; return response(204), nil })}, nil, nil)
	next.now = w.now
	next.runOne(context.Background())
	if sent != 2 || streamState(t, st).Checkpoint != 1 {
		t.Fatalf("sent=%d", sent)
	}
	_ = s
}

func TestLeaseRace(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	appendEvent(t, st, "e", "user.created")
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		updateStream(t, st, func(s *store.EventStream) { s.LeaseOwner = "new-owner" })
		return response(204), nil
	})
	w.runOne(context.Background())
	if streamState(t, st).Checkpoint != 0 || streamState(t, st).LeaseOwner != "new-owner" {
		t.Fatal("stale worker recorded")
	}
}

func TestConfigChangeDuringSendRefreshes(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	appendEvent(t, st, "e", "user.created")
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		updateStream(t, st, func(s *store.EventStream) { s.Name = "updated" })
		return response(204), nil
	})
	if w.runOne(context.Background()) || streamState(t, st).Checkpoint != 0 {
		t.Fatal("recorded against stale configuration version")
	}
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(204), nil })
	if !w.runOne(context.Background()) || streamState(t, st).Checkpoint != 1 || streamState(t, st).Name != "updated" {
		t.Fatal("did not refresh after version conflict")
	}
}

func TestLeaseBoundaries(t *testing.T) {
	w, st, _ := testWorker(t, 500)
	appendEvent(t, st, "one", "user.created")
	appendEvent(t, st, "two", "user.created")
	at := w.now()
	calls := 0
	w.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if dl, ok := r.Context().Deadline(); !ok || time.Until(dl) > 10*time.Second {
			t.Error("unbounded attempt")
		}
		return response(500), nil
	})
	w.now = func() time.Time { return at }
	w.sleep = func(_ context.Context, d time.Duration) error { at = at.Add(d + 10*time.Second); return nil }
	w.runOne(context.Background())
	if calls != 4 || streamState(t, st).Checkpoint != 1 {
		t.Fatalf("calls=%d state=%+v", calls, streamState(t, st))
	}
}

func TestPurgeDuringDelivery(t *testing.T) {
	w, st, _ := testWorker(t, 500)
	appendEvent(t, st, "e", "user.created")
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		_, err := st.Events().PurgeEvents(context.Background(), time.Now().Add(time.Hour), 100)
		if err != nil {
			t.Fatal(err)
		}
		return response(500), nil
	})
	w.runOne(context.Background())
	if streamState(t, st).TotalFailures != 0 {
		t.Fatal("purged event recreated as failed")
	}
	appendEvent(t, st, "new", "user.created")
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(204), nil })
	if !w.runOne(context.Background()) || streamState(t, st).Checkpoint != 2 {
		t.Fatal("purged event wedged worker")
	}
}

func TestBlockedAddresses(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "[::1]", "10.0.0.1", "169.254.169.254", "100.64.0.1"} {
		t.Run(ip, func(t *testing.T) {
			w, _, s := testWorker(t, 204)
			w = NewWorker(w.st, w.keys, events.Config{AllowInsecureHTTP: true}, nil, nil, nil)
			w.sleep = func(context.Context, time.Duration) error { return nil }
			s.Config["webhook_endpoint"] = "http://" + ip + ":1/hook"
			got := w.Deliver(context.Background(), s, []byte(`{}`))
			if len(got) != 4 || got[0].ErrorMessage != "blocked_address" {
				t.Fatal(got)
			}
		})
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	w, _, s := testWorker(t, 204)
	w = NewWorker(w.st, w.keys, events.Config{AllowInsecureHTTP: true}, nil, nil, nil)
	w.sleep = func(context.Context, time.Duration) error { return nil }
	s.Config["webhook_endpoint"] = srv.URL
	w.Deliver(context.Background(), s, []byte(`{}`))
	if requests.Load() != 0 {
		t.Fatal("request reached blocked listener")
	}
}

func TestRedirectCredentials(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	w, _, s := testWorker(t, 204)
	w = NewWorker(w.st, w.keys, events.Config{AllowPrivateNetworks: true, AllowInsecureHTTP: true}, &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}, nil, nil)
	w.sleep = func(context.Context, time.Duration) error { return nil }
	s.Config["webhook_endpoint"] = source.URL
	got := w.Deliver(context.Background(), s, []byte(`{}`))
	if leaked.Load() != 0 || len(got) != 4 || got[0].Status != "failed" {
		t.Fatal("redirect followed or accepted")
	}
}

type runnerFunc func(context.Context, string, string, []byte) error

func (f runnerFunc) RunEventStream(ctx context.Context, t, a string, b []byte) error {
	return f(ctx, t, a, b)
}
func TestActionErrorMaskedAndCancellation(t *testing.T) {
	w, _, s := testWorker(t, 204)
	s.DestType = "action"
	s.Config = map[string]any{"action_id": "act"}
	s.SealedSecret = nil
	w.runner = runnerFunc(func(ctx context.Context, tenant, id string, body []byte) error {
		if tenant != "t" || id != "act" {
			t.Error("action identity")
		}
		return errors.New(`{"token":"never-visible","message":"registered-private"}`)
	})
	ctx := logscrub.WithValues(context.Background(), "registered-private")
	got := w.Deliver(ctx, s, []byte(`{}`))
	if len(got) != 4 || strings.Contains(got[0].ErrorMessage, "registered-private") || strings.Contains(got[0].ErrorMessage, "never-visible") {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := w.Deliver(ctx, s, []byte(`{}`)); len(got) != 0 {
		t.Fatal("cancelled request attempted")
	}
}

func TestSlowReceiverDoesNotBlockSignups(t *testing.T) {
	_, baselineStore, _ := testWorker(t, 204)
	baselineCaptured := events.Wrap(baselineStore, events.Config{})
	baselineStart := time.Now()
	for i := 0; i < 1000; i++ {
		if err := baselineCaptured.Users().Create(context.Background(), &store.User{TenantID: "t", UserID: fmt.Sprintf("u%04d", i), Email: fmt.Sprintf("u%04d@example.com", i)}); err != nil {
			t.Fatal(err)
		}
	}
	baseline := time.Since(baselineStart)
	w, st, _ := testWorker(t, 204)
	captured := events.Wrap(st, events.Config{})
	appendEvent(t, st, "trigger", "user.created")
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan struct{})
	go func() { defer close(done); w.runOne(ctx) }()
	<-entered
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if err := captured.Users().Create(context.Background(), &store.User{TenantID: "t", UserID: fmt.Sprintf("u%04d", i), Email: fmt.Sprintf("u%04d@example.com", i)}); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 30*time.Second {
		t.Fatalf("signup burst took %s", elapsed)
	}
	select {
	case <-done:
		t.Fatal("hanging receiver finished before signups")
	default:
	}
	cancel()
	<-done
	t.Logf("1000 captured signups normal=%s, while receiver blocked=%s; prior relative 10%% target is not asserted", baseline, elapsed)
}

func TestConcurrentLeaseSingleSend(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	appendEvent(t, st, "e", "user.created")
	entered := make(chan struct{})
	release := make(chan struct{})
	w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { close(entered); <-release; return response(204), nil })
	done := make(chan bool, 1)
	go func() { done <- w.runOne(context.Background()) }()
	<-entered
	other := NewWorker(st, w.keys, events.DefaultConfig(), nil, nil, nil)
	other.now = w.now
	if other.runOne(context.Background()) {
		t.Error("other instance acquired live lease")
	}
	close(release)
	if !<-done || streamState(t, st).Checkpoint != 1 {
		t.Fatal("lease winner did not record")
	}
}

type repositoryStore struct {
	store.Store
	repo store.Events
}

func (s repositoryStore) Events() store.Events { return s.repo }

type readHook struct {
	store.Events
	after func()
}

func (r readHook) EventsAfter(ctx context.Context, tid string, seq int64, types []string, take int, settled time.Time) ([]store.TenantEvent, error) {
	rows, err := r.Events.EventsAfter(ctx, tid, seq, types, take, settled)
	r.after()
	return rows, err
}

func TestLeasePreprocessingAndExpiredRecord(t *testing.T) {
	t.Run("preprocessing", func(t *testing.T) {
		w, st, _ := testWorker(t, 204)
		appendEvent(t, st, "e", "user.created")
		at := w.now()
		w.now = func() time.Time { return at }
		calls := 0
		w.st = repositoryStore{Store: st, repo: readHook{Events: st.Events(), after: func() { at = at.Add(9 * time.Second) }}}
		w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(204), nil })
		if w.runOne(context.Background()) || calls != 0 || streamState(t, st).Checkpoint != 0 {
			t.Fatal("sent without a full attempt/record budget")
		}
	})
	t.Run("expires-during-send", func(t *testing.T) {
		w, st, _ := testWorker(t, 204)
		appendEvent(t, st, "e", "user.created")
		at := w.now()
		w.now = func() time.Time { return at }
		w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { at = at.Add(time.Minute); return response(204), nil })
		if w.runOne(context.Background()) || streamState(t, st).Checkpoint != 0 {
			t.Fatal("expired owner recorded")
		}
	})
}

func TestWebhookDiagnosticsAndCancellation(t *testing.T) {
	t.Run("tls", func(t *testing.T) {
		w, _, s := testWorker(t, 204)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS request reached handler") }))
		defer srv.Close()
		w = NewWorker(w.st, w.keys, events.Config{AllowPrivateNetworks: true}, nil, nil, nil)
		w.sleep = func(context.Context, time.Duration) error { return nil }
		s.Config["webhook_endpoint"] = srv.URL
		got := w.Deliver(context.Background(), s, []byte(`{}`))
		if len(got) != 4 || got[0].ErrorMessage != "tls" {
			t.Fatal(got)
		}
	})
	t.Run("connection", func(t *testing.T) {
		w, _, s := testWorker(t, 204)
		w.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("endpoint?token=receiver-secret") })
		got := w.Deliver(context.Background(), s, []byte(`{}`))
		if len(got) != 4 || got[0].ErrorMessage != "connection_error" {
			t.Fatal(got)
		}
	})
	t.Run("cancel-in-backoff", func(t *testing.T) {
		w, _, s := testWorker(t, 500)
		ctx, cancel := context.WithCancel(context.Background())
		w.sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
		got := w.Deliver(ctx, s, []byte(`{}`))
		if len(got) != 1 {
			t.Fatal(got)
		}
	})
	t.Run("hanging-timeout", func(t *testing.T) {
		w, _, s := testWorker(t, 500)
		w.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		got := w.Deliver(ctx, s, []byte(`{}`))
		if len(got) != 1 || got[0].ErrorMessage != "timeout" {
			t.Fatal(got)
		}
	})
}

type unavailableEventsStore struct {
	store.Store
	probes atomic.Int32
}

func (s *unavailableEventsStore) Events() store.Events { return store.UnimplementedEvents{} }
func (s *unavailableEventsStore) CheckEventsSupport(context.Context) error {
	s.probes.Add(1)
	return store.ErrEventsUnavailable
}
func (s *unavailableEventsStore) EventsSupported() bool { return false }
func TestUnsupportedPluginWorkerStops(t *testing.T) {
	w, st, _ := testWorker(t, 204)
	old := &unavailableEventsStore{Store: st}
	w.st = old
	w.sleep = func(context.Context, time.Duration) error { t.Fatal("unsupported plugin spun"); return nil }
	w.Run(context.Background())
	if old.probes.Load() != 1 {
		t.Fatal("capability not checked once")
	}
}

// The real HTTP transport must re-resolve on each failed attempt. A mixed DNS
// answer set and then a private-only rebound set both fail before any dial to
// the loopback listener. The guarded dialer's public->private rebinding case is
// also pinned directly in internal/httpx.
func TestBlockedAddressesDNSRebinding(t *testing.T) {
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	var queries atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buf[:n]) != nil {
				continue
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionDesired: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, q := range query.Questions {
				if q.Type != dnsmessage.TypeA {
					continue
				}
				count := queries.Add(1)
				addresses := [][4]byte{{127, 0, 0, 1}}
				if count == 1 {
					addresses = append(addresses, [4]byte{8, 8, 8, 8})
				}
				for _, addr := range addresses {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: addr}})
				}
			}
			packet, err := reply.Pack()
			if err == nil {
				_, _ = dns.WriteTo(packet, peer)
			}
		}
	}()
	resolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = resolver; dns.Close(); <-done }()
	var requests atomic.Int32
	listener := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer listener.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(listener.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	w, _, s := testWorker(t, 204)
	w = NewWorker(w.st, w.keys, events.Config{AllowInsecureHTTP: true}, nil, nil, nil)
	w.sleep = func(context.Context, time.Duration) error { return nil }
	s.Config["webhook_endpoint"] = "http://rebind.example:" + port + "/hook"
	got := w.Deliver(context.Background(), s, []byte(`{}`))
	if len(got) != 4 || queries.Load() < 4 || requests.Load() != 0 {
		t.Fatalf("attempts=%v DNS A queries=%d listener requests=%d", got, queries.Load(), requests.Load())
	}
	for _, a := range got {
		if a.ErrorMessage != "blocked_address" {
			t.Fatal(got)
		}
	}
}

// Both streams must continue receiving turns when the first never stops being
// due. A fixed clock also catches equal-expiry ties after the initial rotation.
func TestWorkerStreamFairness(t *testing.T) {
	for _, mode := range []string{"continuous", "unsettled-tail"} {
		t.Run(mode, func(t *testing.T) {
			w, _, first := testWorker(t, 204)
			at := time.Now().Add(time.Minute)
			st := memory.NewWithClock(func() time.Time { return at })
			ctx := context.Background()
			if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t", CanonicalHost: "t.example"}); err != nil {
				t.Fatal(err)
			}
			if err := st.Events().CreateEventStream(ctx, first); err != nil {
				t.Fatal(err)
			}
			second := *first
			second.ID, second.Name = "z", "z"
			second.Subscriptions = []string{"user.updated"}
			var err error
			second.SealedSecret, err = SealSecrets(w.keys, &second, map[string]any{"token": "second-private-value"})
			if err != nil {
				t.Fatal(err)
			}
			if err = st.Events().CreateEventStream(ctx, &second); err != nil {
				t.Fatal(err)
			}
			w.st = st
			w.now = func() time.Time { return at }
			var sent []string
			w.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				sent = append(sent, body["a0stream"].(string))
				return response(204), nil
			})
			if mode == "continuous" {
				for i := 0; i < 6; i++ {
					// Keep both streams backlogged while every acquisition uses the
					// same now/until values. The records are already settled.
					at = at.Add(-10 * time.Second)
					appendEvent(t, st, fmt.Sprintf("first-%d", i), "user.created")
					appendEvent(t, st, fmt.Sprintf("second-%d", i), "user.updated")
					at = at.Add(10 * time.Second)
					if !w.runOne(ctx) {
						t.Fatal("backlogged stream made no progress")
					}
				}
				if !reflect.DeepEqual(sent, []string{"s", "z", "s", "z", "s", "z"}) {
					t.Fatalf("stream turns = %v", sent)
				}
			} else {
				at = at.Add(-10 * time.Second)
				appendEvent(t, st, "settled-second", "user.updated")
				at = at.Add(10 * time.Second)
				appendEvent(t, st, "unsettled-first", "user.created")
				for range 4 {
					w.runOne(ctx)
				}
				if !reflect.DeepEqual(sent, []string{"z"}) {
					t.Fatalf("unsettled first stream starved settled second: sent %v", sent)
				}
			}
			state, err := st.Events().GetEventStream(ctx, "t", "z")
			if err != nil || state.Checkpoint == 0 {
				t.Fatalf("second checkpoint=%+v err=%v", state, err)
			}
		})
	}
}
