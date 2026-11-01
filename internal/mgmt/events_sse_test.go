package mgmt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type sseTestClock struct {
	ns      atomic.Int64
	ticks   chan time.Time
	stopped atomic.Int32
}

func (c *sseTestClock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *sseTestClock) advance(d time.Duration) { c.ns.Add(int64(d)); c.ticks <- c.now() }

type sseTestWriter struct {
	header   http.Header
	status   int
	mu       sync.Mutex
	pending  strings.Builder
	messages chan string
	fail     bool
	flushErr atomic.Bool
	onFlush  func(string)
	deadline atomic.Bool
}

func (w *sseTestWriter) Header() http.Header { return w.header }
func (w *sseTestWriter) WriteHeader(n int)   { w.status = n }
func (w *sseTestWriter) Write(b []byte) (int, error) {
	if w.fail {
		return 0, errors.New("SECRET_WRITE")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pending.Write(b)
}
func (w *sseTestWriter) FlushError() error {
	if w.flushErr.Load() {
		return errors.New("SECRET_FLUSH")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.onFlush != nil {
		w.onFlush(w.pending.String())
	}
	w.messages <- w.pending.String()
	w.pending.Reset()
	return nil
}
func (w *sseTestWriter) SetWriteDeadline(d time.Time) error {
	if d.IsZero() {
		w.deadline.Store(true)
	}
	return nil
}
func sseEnv(t *testing.T) (*Handlers, *memory.Store, *sseTestClock) {
	t.Helper()
	c := &sseTestClock{ticks: make(chan time.Time, 10)}
	c.ns.Store(time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC).UnixNano())
	st := memory.NewWithClock(c.now)
	if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "sse", Name: "sse"}); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Store: st, Now: c.now}
	h.sseTicks = func() (<-chan time.Time, func()) { return c.ticks, func() { c.stopped.Add(1) } }
	return h, st, c
}
func sseReq(ctx context.Context, path, header, tid string) *http.Request {
	r := httptest.NewRequest("GET", "https://sse.example/api/v2/events"+path, nil)
	if header != "" {
		r.Header.Set("Last-Event-ID", header)
	}
	ctx = WithCaller(ctx, Caller{Kind: M2M, Scopes: []string{"read:events"}})
	return r.WithContext(tenant.WithResolved(ctx, tenant.Resolved{Tenant: &store.Tenant{ID: tid}, Host: "sse.example"}))
}
func sseStart(t *testing.T, h *Handlers, path, header string) (*sseTestWriter, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	w := &sseTestWriter{header: make(http.Header), messages: make(chan string, 1000)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.LogMiddleware(http.HandlerFunc(h.SubscribeEvents)).ServeHTTP(w, sseReq(ctx, path, header, "sse"))
	}()
	t.Cleanup(func() { cancel(); sseDone(t, done) })
	return w, cancel, done
}
func sseDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SSE did not return")
	}
}
func sseMessage(t *testing.T, w *sseTestWriter) string {
	t.Helper()
	select {
	case m := <-w.messages:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no SSE flush")
		return ""
	}
}
func sseConnected(t *testing.T, w *sseTestWriter) {
	t.Helper()
	m := sseMessage(t, w)
	if !strings.Contains(m, ":connected\n\n") || !strings.Contains(m, "retry: 2000\n\n") || !w.deadline.Load() {
		t.Fatalf("connect %q deadline %v", m, w.deadline.Load())
	}
}
func sseOffset(n int64) string { return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprint(n))) }
func sseAppend(t *testing.T, st store.Store, tid, id, typ string, at time.Time) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"type": typ, "id": id, "data": map[string]any{"object": map[string]any{"name": "test"}}})
	es := []store.TenantEvent{{TenantID: tid, ID: id, Type: typ, Time: at, Body: body}}
	if err := st.Events().AppendEvents(t.Context(), es); err != nil {
		t.Fatal(err)
	}
	return es[0].Seq
}
func TestSSEStreamsLive(t *testing.T) {
	h, st, c := sseEnv(t)
	sseAppend(t, st, "sse", "old", "user.created", c.now())
	w, _, _ := sseStart(t, h, "", "")
	sseConnected(t, w)
	n := sseAppend(t, st, "sse", "new", "user.created", c.now())
	c.advance(3 * time.Second)
	m := sseMessage(t, w)
	if !strings.Contains(m, "event: user.created\nid: "+sseOffset(n)+"\ndata: ") || strings.Contains(m, "old") || strings.Contains(m, "a0stream") || strings.Contains(m, "a0purpose") {
		t.Fatal(m)
	}
}
func TestSSEResumeLastEventID(t *testing.T) {
	h, st, c := sseEnv(t)
	a := sseAppend(t, st, "sse", "a", "user.created", c.now())
	b := sseAppend(t, st, "sse", "b", "user.created", c.now())
	c.advance(3 * time.Second)
	w, cancel, done := sseStart(t, h, "?from=bad", sseOffset(a))
	sseConnected(t, w)
	m := sseMessage(t, w)
	if !strings.Contains(m, "\"id\":\"b\"") || !strings.Contains(m, "id: "+sseOffset(b)) {
		t.Fatal(m)
	}
	cancel()
	sseDone(t, done)
	w2, _, _ := sseStart(t, h, "?from="+sseOffset(b), "")
	sseConnected(t, w2)
	sseAppend(t, st, "sse", "c", "user.created", c.now())
	c.advance(3 * time.Second)
	m = sseMessage(t, w2)
	if !strings.Contains(m, "\"id\":\"c\"") || strings.Contains(m, "\"id\":\"b\"") {
		t.Fatal(m)
	}
}
func TestSSEFromTimestamp(t *testing.T) {
	h, st, c := sseEnv(t)
	from := c.now()
	sseAppend(t, st, "sse", "past", "user.created", from.Add(-time.Second))
	for i := 0; i < 105; i++ {
		sseAppend(t, st, "sse", fmt.Sprint(i), "user.created", from.Add(time.Duration(105-i)*time.Second))
	}
	c.advance(3 * time.Second)
	w, _, _ := sseStart(t, h, "?from_timestamp="+from.Format(time.RFC3339), "")
	sseConnected(t, w)
	for i := 0; i < 105; i++ {
		m := sseMessage(t, w)
		if !strings.Contains(m, fmt.Sprintf("\"id\":\"%d\"", i)) {
			t.Fatal(i, m)
		}
	}
	sseAppend(t, st, "sse", "older-future", "user.created", from.Add(time.Second))
	c.advance(3 * time.Second)
	if m := sseMessage(t, w); !strings.Contains(m, "older-future") {
		t.Fatal(m)
	}
	sseAppend(t, st, "sse", "too-old", "user.created", from.Add(-time.Second))
	c.advance(30 * time.Second)
	for {
		m := sseMessage(t, w)
		if strings.Contains(m, "too-old") {
			t.Fatal(m)
		}
		if strings.Contains(m, "event: offset-only") {
			break
		}
	}
}
func TestSSEEventTypeFilter(t *testing.T) {
	h, st, c := sseEnv(t)
	sseAppend(t, st, "sse", "a", "user.created", c.now())
	b := sseAppend(t, st, "sse", "b", "user.updated", c.now())
	c.advance(3 * time.Second)
	w, _, _ := sseStart(t, h, "?from="+sseOffset(0)+"&event_type=user.created&event_type=organization.created", "")
	sseConnected(t, w)
	if m := sseMessage(t, w); !strings.Contains(m, "\"id\":\"a\"") {
		t.Fatal(m)
	}
	c.advance(30 * time.Second)
	for {
		m := sseMessage(t, w)
		if strings.Contains(m, "user.updated") {
			t.Fatal(m)
		}
		if strings.Contains(m, "event: offset-only") {
			if !strings.Contains(m, "id: "+sseOffset(b)) {
				t.Fatal(m)
			}
			break
		}
	}
}
func TestSSEBadParams(t *testing.T) {
	h, _, _ := sseEnv(t)
	for _, q := range []string{"?from=bad", "?from=MA==", "?from=" + sseOffset(-1), "?from=" + base64.RawURLEncoding.EncodeToString([]byte("01")), "?from=" + strings.Repeat("a", 1025), "?event_type=unknown", "?event_type=", "?from_timestamp=2026-11-01", "?from_timestamp=2026-11-01T12:00:00.1Z", "?from_timestamp=2026-11-01T12:00:00+00:00", "?from=&from_timestamp=2026-11-01T12:00:00Z", "?from=MA&from=MQ", "?unknown=x", "?from=%ZZ"} {
		t.Run(q, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.SubscribeEvents(w, sseReq(t.Context(), q, "", "sse"))
			if w.Code != 400 {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
}
func TestSSEExpiredCursor(t *testing.T) {
	h, st, c := sseEnv(t)
	a := sseAppend(t, st, "sse", "a", "user.created", c.now().Add(-time.Hour))
	sseAppend(t, st, "sse", "b", "user.created", c.now())
	_, err := st.Events().PurgeEvents(t.Context(), c.now().Add(-time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.SubscribeEvents(w, sseReq(t.Context(), "?from="+sseOffset(a-1), "", "sse"))
	if w.Code != 410 {
		t.Fatal(w.Code, w.Body)
	}
}
func TestSSEConnectionLimit(t *testing.T) {
	h, _, _ := sseEnv(t)
	h.EventsConfig.MaxConnections = 1
	w, cancel, done := sseStart(t, h, "", "")
	sseConnected(t, w)
	denied := httptest.NewRecorder()
	h.SubscribeEvents(denied, sseReq(t.Context(), "", "", "sse"))
	if denied.Code != 403 || !strings.Contains(denied.Body.String(), "Maximum concurrent event stream connections reached. Please close existing connections.") {
		t.Fatal(denied.Code, denied.Body)
	}
	cancel()
	sseDone(t, done)
	w2, _, _ := sseStart(t, h, "", "")
	sseConnected(t, w2)
}
func TestSSEHeartbeatAndCycle(t *testing.T) {
	h, _, c := sseEnv(t)
	w, _, done := sseStart(t, h, "", "")
	sseConnected(t, w)
	c.advance(15 * time.Second)
	if m := sseMessage(t, w); m != ": heartbeat\n\n" {
		t.Fatal(m)
	}
	c.advance(15 * time.Second)
	if m := sseMessage(t, w); m != ": heartbeat\n\n" {
		t.Fatal(m)
	}
	if m := sseMessage(t, w); !strings.Contains(m, "event: offset-only") {
		t.Fatal(m)
	}
	c.advance(270 * time.Second)
	sseDone(t, done)
	if c.stopped.Load() != 1 {
		t.Fatal("ticker leaked")
	}
}
func TestSSETenantIsolation(t *testing.T) {
	h, st, c := sseEnv(t)
	sseAppend(t, st, "other", "other", "user.created", c.now())
	sseAppend(t, st, "sse", "ours", "user.created", c.now())
	c.advance(3 * time.Second)
	w, _, _ := sseStart(t, h, "?from="+sseOffset(1), "")
	sseConnected(t, w)
	if m := sseMessage(t, w); strings.Contains(m, "other") || !strings.Contains(m, "ours") {
		t.Fatal(m)
	}
}

// A real net/http connection must receive a later flush after the server's
// original write deadline has passed. The authenticated middleware also must
// hand the original transport writer directly to the SSE handler.
func TestSSERealServerFlushAndWriteDeadline(t *testing.T) {
	h, st, c := sseEnv(t)
	h.sseTicks = nil
	var original atomic.Bool
	handle := h.LogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, captured := w.(interface{ Unwrap() http.ResponseWriter })
		original.Store(!captured)
		h.SubscribeEvents(w, r)
	}))
	done := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		r = r.WithContext(sseReq(r.Context(), "", "", "sse").Context())
		handle.ServeHTTP(w, r)
	}))
	srv.Config.WriteTimeout = 50 * time.Millisecond
	srv.Start()
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL + "/api/v2/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(resp.Status)
	}
	reader := bufio.NewReader(resp.Body)
	readMessage := func() string {
		t.Helper()
		var b strings.Builder
		for {
			line, e := reader.ReadString('\n')
			if e != nil {
				t.Fatal(e)
			}
			b.WriteString(line)
			if line == "\n" {
				return b.String()
			}
		}
	}
	if m := readMessage(); m != ":connected\n\n" {
		t.Fatal(m)
	}
	if m := readMessage(); m != "retry: 2000\n\n" {
		t.Fatal(m)
	}
	if !original.Load() {
		t.Fatal("Plan 31 capture wrapper retained")
	}
	sseAppend(t, st, "sse", "later", "user.created", c.now())
	c.ns.Add(int64(3 * time.Second))
	if m := readMessage(); !strings.Contains(m, "later") {
		t.Fatal(m)
	}
	resp.Body.Close()
	sseDone(t, done)
	if len(h.sseConnections) != 0 {
		t.Fatal("real disconnect leaked slot")
	}
}

func TestSSEHeaderTimestampPrecedence(t *testing.T) {
	h, st, c := sseEnv(t)
	a := sseAppend(t, st, "sse", "a", "user.created", c.now())
	sseAppend(t, st, "sse", "b", "user.created", c.now())
	c.advance(3 * time.Second)
	w, _, _ := sseStart(t, h, "?from_timestamp=invalid", sseOffset(a))
	sseConnected(t, w)
	if m := sseMessage(t, w); !strings.Contains(m, "\"id\":\"b\"") {
		t.Fatal(m)
	}
	bad := httptest.NewRecorder()
	h.SubscribeEvents(bad, sseReq(t.Context(), "?from=bad&from_timestamp=invalid", sseOffset(a), "sse"))
	if bad.Code != 400 {
		t.Fatal(bad.Code, bad.Body)
	}
}

type sseFaultStore struct {
	store.Store
	readErr *error
}

func (s sseFaultStore) Events() store.Events {
	return sseFaultEvents{Events: s.Store.Events(), err: s.readErr}
}
func (s sseFaultStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(sseFaultStore{tx, s.readErr}) })
}

type sseFaultEvents struct {
	store.Events
	err *error
}

func (s sseFaultEvents) OldestEventSeq(ctx context.Context, tid string) (int64, error) {
	if *s.err != nil {
		return 0, *s.err
	}
	return s.Events.OldestEventSeq(ctx, tid)
}
func TestSSEStoreErrorsAndRelease(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{{store.ErrEventsUnavailable, 501, "events_unavailable"}, {errors.New("SECRET_STORE"), 500, "internal_error"}} {
		t.Run(tc.code, func(t *testing.T) {
			h, st, _ := sseEnv(t)
			err := tc.err
			var diagnostics bytes.Buffer
			h.Log = slog.New(slog.NewTextHandler(&diagnostics, nil))
			h.Store = sseFaultStore{st, &err}
			w := httptest.NewRecorder()
			h.SubscribeEvents(w, sseReq(t.Context(), "", "", "sse"))
			if w.Code != tc.status || strings.Contains(w.Body.String(), "SECRET_STORE") || !strings.Contains(w.Body.String(), tc.code) {
				t.Fatal(w.Code, w.Body)
			}
			if strings.Contains(diagnostics.String(), "SECRET_STORE") {
				t.Fatal("storage diagnostic leaked:", diagnostics.String())
			}
			if len(h.sseConnections) != 0 {
				t.Fatal("connection leaked")
			}
		})
	}
	for _, tc := range []struct {
		err  error
		code string
	}{{store.ErrInvalid, "invalid_cursor"}, {context.DeadlineExceeded, "timeout"}, {errors.New("SECRET_STORE"), "processing_error"}, {errSSEExpired, "cursor_expired"}} {
		t.Run(tc.code, func(t *testing.T) {
			h, st, c := sseEnv(t)
			var err error
			h.Store = sseFaultStore{st, &err}
			w, _, done := sseStart(t, h, "", "")
			sseConnected(t, w)
			err = tc.err
			c.advance(time.Second)
			m := sseMessage(t, w)
			if !strings.Contains(m, "event: error\ndata: {\"code\":\""+tc.code+"\"}") || strings.Contains(m, "SECRET") {
				t.Fatal(m)
			}
			sseDone(t, done)
			if len(h.sseConnections) != 0 || c.stopped.Load() != 1 {
				t.Fatal("resource leak")
			}
		})
	}
}
func TestSSEWriterErrorReleasesConnection(t *testing.T) {
	h, _, _ := sseEnv(t)
	w := &sseTestWriter{header: make(http.Header), fail: true}
	h.SubscribeEvents(w, sseReq(t.Context(), "", "", "sse"))
	if len(h.sseConnections) != 0 {
		t.Fatal("writer error leaked semaphore")
	}
}

func TestSSEOffsetDoesNotPassUnsettled(t *testing.T) {
	h, st, c := sseEnv(t)
	w, cancel, done := sseStart(t, h, "?event_type=user.created", "")
	sseConnected(t, w)
	c.ns.Add(int64(29 * time.Second))
	n := sseAppend(t, st, "sse", "pending", "user.created", c.now())
	c.advance(time.Second)
	for {
		m := sseMessage(t, w)
		if strings.Contains(m, "event: offset-only") {
			if !strings.Contains(m, "id: "+sseOffset(0)) {
				t.Fatal(m)
			}
			break
		}
	}
	cancel()
	sseDone(t, done)
	w2, _, _ := sseStart(t, h, "?from="+sseOffset(0), "")
	sseConnected(t, w2)
	c.advance(2 * time.Second)
	m := sseMessage(t, w2)
	if !strings.Contains(m, "pending") || !strings.Contains(m, "id: "+sseOffset(n)) {
		t.Fatal(m)
	}
}
func TestSSEEmptyRetainedRingCursor(t *testing.T) {
	h, st, c := sseEnv(t)
	sseAppend(t, st, "sse", "gone1", "user.created", c.now().Add(-time.Hour))
	sseAppend(t, st, "sse", "gone2", "user.created", c.now().Add(-time.Hour))
	_, err := st.Events().PurgeEvents(t.Context(), c.now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	w, _, done := sseStart(t, h, "?from="+sseOffset(0), "")
	sseConnected(t, w)
	sseAppend(t, st, "sse", "retained", "user.created", c.now())
	c.advance(3 * time.Second)
	if m := sseMessage(t, w); !strings.Contains(m, "cursor_expired") {
		t.Fatal(m)
	}
	sseDone(t, done)
}
func TestSSEResumeConcurrentWriters(t *testing.T) {
	h, st, c := sseEnv(t)
	w, cancel, done := sseStart(t, h, "", "")
	sseConnected(t, w)
	appended := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	second := make(chan error, 1)
	secondStarted := make(chan struct{})
	go func() {
		first <- st.WithTx(t.Context(), func(tx store.Store) error {
			err := tx.Events().AppendEvents(t.Context(), []store.TenantEvent{{TenantID: "sse", ID: "first", Type: "user.created", Time: c.now(), Body: []byte(`{"id":"first"}`)}})
			close(appended)
			<-release
			return err
		})
	}()
	<-appended
	go func() {
		close(secondStarted)
		second <- st.WithTx(t.Context(), func(tx store.Store) error {
			return tx.Events().AppendEvents(t.Context(), []store.TenantEvent{{TenantID: "sse", ID: "second", Type: "user.created", Time: c.now().Add(-time.Hour), Body: []byte(`{"id":"second"}`)}})
		})
	}()
	<-secondStarted
	// The second business operation attempts to finish while the first append is
	// held. The store serializes visibility through commit, beyond settle time.
	c.ns.Add(int64(35 * time.Second))
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	c.advance(3 * time.Second)
	var a string
	for {
		m := sseMessage(t, w)
		if strings.Contains(m, "event: user.created") {
			a = m
			break
		}
	}
	if !strings.Contains(a, "first") {
		t.Fatal(a)
	}
	cancel()
	sseDone(t, done)
	w2, _, _ := sseStart(t, h, "?from="+sseOffset(0), sseOffset(1))
	sseConnected(t, w2)
	if m := sseMessage(t, w2); !strings.Contains(m, "second") || strings.Contains(m, "first") {
		t.Fatal(m)
	}
}

func TestSSEDefaultLimitAndIndependentTenants(t *testing.T) {
	h, st, _ := sseEnv(t)
	for i := 0; i < 4; i++ {
		w, _, _ := sseStart(t, h, "", "")
		sseConnected(t, w)
	}
	denied := httptest.NewRecorder()
	h.SubscribeEvents(denied, sseReq(t.Context(), "", "", "sse"))
	if denied.Code != 403 {
		t.Fatal(denied.Code, denied.Body)
	}
	if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "other", Name: "other"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &sseTestWriter{header: make(http.Header), messages: make(chan string, 100)}
	done := make(chan struct{})
	go func() { defer close(done); h.SubscribeEvents(w, sseReq(ctx, "", "", "other")) }()
	sseConnected(t, w)
	cancel()
	sseDone(t, done)
}
func TestSSEPayloadAndMalformedTerminal(t *testing.T) {
	h, st, c := sseEnv(t)
	es := []store.TenantEvent{{TenantID: "sse", ID: "one", Type: "user.created", Time: c.now(), Body: []byte(`{"id":"one","a0stream":"private","a0purpose":"test","data":{"object":{"name":"newline\nvalue"}}}`)}, {TenantID: "sse", ID: "bad", Type: "user.created", Time: c.now(), Body: []byte(`SECRET_BAD_BODY`)}}
	if err := st.Events().AppendEvents(t.Context(), es); err != nil {
		t.Fatal(err)
	}
	c.advance(3 * time.Second)
	w, _, done := sseStart(t, h, "?from="+sseOffset(0), "")
	sseConnected(t, w)
	m := sseMessage(t, w)
	if strings.Contains(m, "a0stream") || strings.Contains(m, "a0purpose") || !strings.Contains(m, `newline\nvalue`) {
		t.Fatal(m)
	}
	m = sseMessage(t, w)
	if !strings.Contains(m, "processing_error") || strings.Contains(m, "SECRET") {
		t.Fatal(m)
	}
	sseDone(t, done)
}
func TestSSEExpiryAfterConnection(t *testing.T) {
	h, st, c := sseEnv(t)
	sseAppend(t, st, "sse", "baseline", "user.created", c.now().Add(-time.Hour))
	w, _, done := sseStart(t, h, "", "")
	sseConnected(t, w)
	sseAppend(t, st, "sse", "gone1", "user.created", c.now().Add(-time.Hour))
	sseAppend(t, st, "sse", "gone2", "user.created", c.now().Add(-time.Hour))
	_, err := st.Events().PurgeEvents(t.Context(), c.now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	sseAppend(t, st, "sse", "kept", "user.created", c.now())
	c.advance(3 * time.Second)
	if m := sseMessage(t, w); !strings.Contains(m, "cursor_expired") {
		t.Fatal(m)
	}
	sseDone(t, done)
}
func TestSSEFutureCursorAndOldestBoundary(t *testing.T) {
	h, st, c := sseEnv(t)
	a := sseAppend(t, st, "sse", "a", "user.created", c.now().Add(-time.Hour))
	b := sseAppend(t, st, "sse", "b", "user.created", c.now())
	_, err := st.Events().PurgeEvents(t.Context(), c.now().Add(-time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	c.advance(3 * time.Second)
	w, _, _ := sseStart(t, h, "?from="+sseOffset(a), "")
	sseConnected(t, w)
	if m := sseMessage(t, w); !strings.Contains(m, "id: "+sseOffset(b)) {
		t.Fatal(m)
	}
	future, _, _ := sseStart(t, h, "?from="+sseOffset(b+100), "")
	sseConnected(t, future)
}

type sseProbeFault struct {
	store.Store
	err error
}

func (s sseProbeFault) CheckEventsSupport(context.Context) error { return s.err }
func (s sseProbeFault) EventsSupported() bool                    { return false }
func TestSSECapabilityProbe(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{{store.ErrEventsUnavailable, 501}, {errors.New("SECRET_PROBE"), 500}} {
		h, st, _ := sseEnv(t)
		var diagnostics bytes.Buffer
		h.Log = slog.New(slog.NewTextHandler(&diagnostics, nil))
		h.Store = sseProbeFault{st, tc.err}
		w := httptest.NewRecorder()
		h.SubscribeEvents(w, sseReq(t.Context(), "", "", "sse"))
		if w.Code != tc.want || strings.Contains(w.Body.String(), "SECRET") || strings.Contains(diagnostics.String(), "SECRET") {
			t.Fatal(w.Code, w.Body, diagnostics.String())
		}
		if len(h.sseConnections) != 0 {
			t.Fatal("probe consumed connection slot")
		}
	}
}

func TestSSETimestampAtGoZeroTime(t *testing.T) {
	h, st, c := sseEnv(t)
	sseAppend(t, st, "sse", "gone", "user.created", c.now().Add(-time.Hour))
	sseAppend(t, st, "sse", "kept", "user.created", c.now())
	_, err := st.Events().PurgeEvents(t.Context(), c.now().Add(-time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	c.advance(3 * time.Second)
	w, _, _ := sseStart(t, h, "?from_timestamp=0001-01-01T00:00:00Z", "")
	sseConnected(t, w)
	if m := sseMessage(t, w); !strings.Contains(m, "kept") {
		t.Fatal(m)
	}
}

func TestSSEFlushFailureReleasesTicker(t *testing.T) {
	h, _, c := sseEnv(t)
	w, _, done := sseStart(t, h, "", "")
	sseConnected(t, w)
	w.flushErr.Store(true)
	c.advance(15 * time.Second)
	sseDone(t, done)
	if c.stopped.Load() != 1 || len(h.sseConnections) != 0 {
		t.Fatal("flush failure leaked resources")
	}
}

func TestSSEHeartbeatDuringBacklog(t *testing.T) {
	h, st, c := sseEnv(t)
	for i := 0; i < 10; i++ {
		sseAppend(t, st, "sse", fmt.Sprint(i), "user.created", c.now())
	}
	c.advance(3 * time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &sseTestWriter{header: make(http.Header), messages: make(chan string, 100), onFlush: func(m string) {
		if strings.HasPrefix(m, "event: user.created") {
			c.ns.Add(int64(16 * time.Second))
		}
	}}
	done := make(chan struct{})
	go func() { defer close(done); h.SubscribeEvents(w, sseReq(ctx, "?from="+sseOffset(0), "", "sse")) }()
	t.Cleanup(func() { cancel(); sseDone(t, done) })
	sseConnected(t, w)
	if m := sseMessage(t, w); !strings.Contains(m, "event: user.created") {
		t.Fatal(m)
	}
	if m := sseMessage(t, w); m != ": heartbeat\n\n" {
		t.Fatalf("heartbeat delayed by backlog: %q", m)
	}
}

func TestSSEFreshEmptyTenant(t *testing.T) {
	for _, timestamp := range []bool{false, true} {
		t.Run(fmt.Sprint(timestamp), func(t *testing.T) {
			h, st, c := sseEnv(t)
			sseAppend(t, st, "other", "other1", "user.created", c.now())
			sseAppend(t, st, "other", "other2", "user.created", c.now())
			query := ""
			if timestamp {
				query = "?from_timestamp=" + c.now().Format(time.RFC3339)
			}
			w, _, _ := sseStart(t, h, query, "")
			sseConnected(t, w)
			sseAppend(t, st, "sse", "new", "user.created", c.now())
			c.advance(3 * time.Second)
			if m := sseMessage(t, w); !strings.Contains(m, "\"id\":\"new\"") {
				t.Fatal(m)
			}
		})
	}
}
