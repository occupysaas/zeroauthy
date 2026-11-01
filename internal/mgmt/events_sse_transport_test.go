package mgmt

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// net.Pipe implements actual blocking I/O and transport deadlines. Both Write
// and Flush are exercised without a goroutine pretending a blocked send ended.
type sseBlockedTransport struct {
	conn          net.Conn
	header        http.Header
	phase         string
	entered       chan struct{}
	once          sync.Once
	buffer        []byte
	deadlineMu    sync.Mutex
	deadline      time.Time
	cleared       bool
	expireEntered chan struct{}
	expireReturn  chan struct{}
	expireOnce    sync.Once
}

func (w *sseBlockedTransport) Header() http.Header { return w.header }
func (w *sseBlockedTransport) WriteHeader(int)     {}
func (w *sseBlockedTransport) Write(b []byte) (int, error) {
	if w.phase == "flush" {
		w.buffer = append(w.buffer, b...)
		return len(b), nil
	}
	w.once.Do(func() { close(w.entered) })
	return w.conn.Write(b)
}
func (w *sseBlockedTransport) FlushError() error {
	w.once.Do(func() { close(w.entered) })
	_, err := w.conn.Write(w.buffer)
	return err
}
func (w *sseBlockedTransport) SetWriteDeadline(d time.Time) error {
	w.deadlineMu.Lock()
	w.deadline = d
	w.cleared = w.cleared || d.IsZero()
	w.deadlineMu.Unlock()
	err := w.conn.SetWriteDeadline(d)
	if !d.IsZero() && !d.After(time.Now()) && w.expireEntered != nil {
		w.expireOnce.Do(func() { close(w.expireEntered) })
		<-w.expireReturn
	}
	return err
}
func TestSSEBlockedTransport(t *testing.T) {
	for _, phase := range []string{"write", "flush"} {
		for _, cause := range []string{"cycle", "cancel"} {
			t.Run(phase+"/"+cause, func(t *testing.T) {
				h, _, c := sseEnv(t)
				h.EventsConfig.MaxConnections = 1
				server, client := net.Pipe()
				defer server.Close()
				defer client.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				w := &sseBlockedTransport{conn: server, header: make(http.Header), phase: phase, entered: make(chan struct{})}
				done := make(chan struct{})
				go func() { defer close(done); h.SubscribeEvents(w, sseReq(ctx, "", "", "sse")) }()
				t.Cleanup(func() { cancel(); server.Close(); sseDone(t, done) })
				select {
				case <-w.entered:
				case <-time.After(time.Second):
					t.Fatal("transport never blocked")
				}
				denied := httptest.NewRecorder()
				h.SubscribeEvents(denied, sseReq(t.Context(), "", "", "sse"))
				if denied.Code != 403 {
					t.Fatal("blocked stream did not hold slot", denied.Code)
				}
				w.deadlineMu.Lock()
				deadline, cleared := w.deadline, w.cleared
				w.deadlineMu.Unlock()
				// A cycle-length deadline replaces the server deadline before the first I/O.
				if !cleared || deadline.IsZero() || deadline.After(time.Now().Add(5*time.Minute)) {
					t.Error("transport has no bounded cycle deadline", deadline, cleared)
				}
				if cause == "cancel" {
					cancel()
				} else {
					c.advance(5 * time.Minute)
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("blocked " + phase + " survived " + cause)
					server.Close()
					sseDone(t, done)
				}
				if len(h.sseConnections) != 0 {
					t.Fatal("blocked transport leaked tenant slot")
				}
				if c.stopped.Load() != 1 {
					t.Fatal("blocked transport leaked polling timer")
				}
				next, nextCancel, nextDone := sseStart(t, h, "", "")
				sseConnected(t, next)
				nextCancel()
				sseDone(t, nextDone)
			})
		}
	}
}

func TestSSEDeadlineHookJoinedBeforeReturn(t *testing.T) {
	h, _, c := sseEnv(t)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &sseBlockedTransport{conn: server, header: make(http.Header), phase: "write", entered: make(chan struct{}), expireEntered: make(chan struct{}), expireReturn: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); h.SubscribeEvents(w, sseReq(ctx, "", "", "sse")) }()
	var release sync.Once
	unblock := func() { release.Do(func() { close(w.expireReturn) }) }
	t.Cleanup(func() { unblock(); cancel(); server.Close(); sseDone(t, done) })
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("write never blocked")
	}
	cancel()
	select {
	case <-w.expireEntered:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not expire transport")
	}
	// The I/O is already released, but SetWriteDeadline is held inside the
	// cancellation hook. ServeHTTP must join that hook before returning/reuse.
	select {
	case <-done:
		t.Fatal("handler returned while deadline hook was active")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	sseDone(t, done)
	if c.stopped.Load() != 1 || len(h.sseConnections) != 0 {
		t.Fatal("cleanup incomplete")
	}
}

type sseSmallWindowListener struct{ net.Listener }

func (l sseSmallWindowListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		err = conn.(*net.TCPConn).SetWriteBuffer(1024)
		if err != nil {
			conn.Close()
		}
	}
	return conn, err
}

type sseLargeWrite struct {
	http.ResponseWriter
	entered  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func (w *sseLargeWrite) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *sseLargeWrite) Write(b []byte) (int, error) {
	if len(b) > 65536 {
		w.once.Do(func() { close(w.entered) })
		defer close(w.finished)
	}
	return w.ResponseWriter.Write(b)
}
func TestSSEStalledTCPReaderCycle(t *testing.T) {
	h, st, c := sseEnv(t)
	body, err := json.Marshal(map[string]any{"id": "large", "data": strings.Repeat("x", 4<<20)})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Events().AppendEvents(t.Context(), []store.TenantEvent{{TenantID: "sse", ID: "large", Type: "user.created", Time: c.now(), Body: body}}); err != nil {
		t.Fatal(err)
	}
	c.advance(3 * time.Second)
	entered, finished, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) != 1 {
			t.Error("unexpected extra request")
			return
		}
		defer close(done)
		r = r.WithContext(sseReq(r.Context(), "", "", "sse").Context())
		h.SubscribeEvents(&sseLargeWrite{ResponseWriter: w, entered: entered, finished: finished}, r)
	}))
	srv.Listener = sseSmallWindowListener{srv.Listener}
	srv.Start()
	defer srv.Close()
	addr, err := net.ResolveTCPAddr("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprintf(conn, "GET /api/v2/events?from=MA HTTP/1.1\r\nHost: sse.example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if line == "\r\n" {
			break
		}
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("large write not reached")
	}
	select {
	case <-finished:
		t.Fatal("fixture did not block the large TCP write")
	case <-time.After(20 * time.Millisecond):
	}
	c.advance(5 * time.Minute)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("stalled TCP reader survived cycle")
		conn.Close()
		sseDone(t, done)
	}
	if len(h.sseConnections) != 0 || c.stopped.Load() != 1 {
		t.Fatal("TCP transport leaked stream resources")
	}
}

func TestSSETransportRealLifetimeWithFrozenClock(t *testing.T) {
	h, _, c := sseEnv(t)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	w := &sseBlockedTransport{conn: server, header: make(http.Header), phase: "write", entered: make(chan struct{})}
	started := h.now()
	deadline := time.Now().Add(30 * time.Millisecond)
	transport := &sseTransport{controller: http.NewResponseController(w), started: started, realDeadline: deadline, now: h.now}
	// Backward logical clock movement cannot extend the real transport lifetime.
	c.ns.Add(-int64(time.Hour))
	if err := transport.prepare(); err != nil {
		t.Fatal(err)
	}
	w.deadlineMu.Lock()
	actual := w.deadline
	w.deadlineMu.Unlock()
	if !actual.Equal(deadline) {
		t.Fatal("real lifetime changed", actual, deadline)
	}
	ctx, _, rawCleanup := h.sseLifetime(t.Context(), transport)
	var cleanupOnce sync.Once
	cleanup := func() { cleanupOnce.Do(rawCleanup) }
	defer cleanup()
	done := make(chan error, 1)
	go func() { _, err := w.Write([]byte("blocked")); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked transport unexpectedly wrote")
		}
	case <-time.After(time.Second):
		t.Fatal("real deadline did not stop write")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("frozen clock prevented real lifetime cancellation")
	}
	cleanupDone := make(chan struct{})
	go func() { defer close(cleanupDone); cleanup() }()
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("real lifetime watcher leaked")
	}
	// Explicit completion proves the watcher joined; deferred cleanup is idempotent.
	if c.stopped.Load() != 1 {
		t.Fatal("real lifetime ticker leaked")
	}
}
