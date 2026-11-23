package adhub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func newHub(e *env) *Hub {
	h := &Hub{Service: e.svc, ReplicaID: "replica-a"}
	e.svc.Hub = h
	return h
}

// TestHubAuthentication is Review Focus 1: only a JWT signed by a
// provisioned connector key, for this tenant's connection and realm, fresh
// and not replayed, gets a socket.
func TestHubAuthentication(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	srv := hubServer(t, e, h, e.ta)
	k := newConnectorKey(t, 2048)
	register(t, e, k)
	stranger := newConnectorKey(t, 2048)

	try := func(token string) string {
		ws, err := dialHub(t, srv)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.Close()
		return authenticateRaw(t, ws, token)
	}
	exp := e.now.Add(time.Minute)
	good := hubToken(t, k, "corp", "urn:auth0:acme:corp", exp)
	if got := try(good); got != evAuthenticated {
		t.Fatalf("provisioned connector: %s", got)
	}
	waitFor(t, "session row removed after close", func() bool { return len(sessions(t, e, e.conn)) == 0 })
	for name, token := range map[string]string{
		"replayed token":    good,
		"unprovisioned key": hubToken(t, stranger, "corp", "urn:auth0:acme:corp", exp),
		"wrong issuer":      hubToken(t, k, "other", "urn:auth0:acme:corp", exp),
		"wrong audience":    hubToken(t, k, "corp", "urn:auth0:beta:corp", exp),
		"expired":           hubToken(t, k, "corp", "urn:auth0:acme:corp", e.now.Add(-2*time.Minute)),
		"lifetime too long": hubToken(t, k, "corp", "urn:auth0:acme:corp", e.now.Add(time.Hour)),
		"not a jwt":         "nonsense",
	} {
		if got := try(token); got != evAuthenticationFailure {
			t.Errorf("%s: %s", name, got)
		}
	}
	// The other tenant's connector (its key provisioned there) cannot use
	// this tenant's hub, even for a connection with the same name.
	other := newConnectorKey(t, 2048)
	rec := httptest.NewRecorder()
	e.svc.TicketConfigure(rec, request(e.tb, "POST", "", `{"certs":["`+other.b64()+`"]}`), e.ticket(e.tb, e.connB))
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	if got := try(hubToken(t, other, "corp", "urn:auth0:acme:corp", exp)); got != evAuthenticationFailure {
		t.Errorf("other tenant's connector: %s", got)
	}
	// A first message other than authenticate is refused.
	ws, err := dialHub(t, srv)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ws.Write([]byte(`{"n":"authenticate_user","p":{}}`))
	var raw []byte
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := websocket.Message.Receive(ws, &raw); err != nil || string(raw) != `{"n":"authentication_failure"}` {
		t.Fatalf("first message not authenticate: %s %v", raw, err)
	}
	ws.Close()
}

// The hub requires TLS (LR38a-2) and a WebSocket upgrade.
func TestHubRequiresTLS(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	for name, tc := range map[string]struct {
		tls    bool
		header map[string]string
		want   int
	}{
		"plain http":          {false, map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"}, http.StatusForbidden},
		"forwarded untrusted": {false, map[string]string{"Upgrade": "websocket", "X-Forwarded-Proto": "https"}, http.StatusForbidden},
		"not a websocket":     {true, nil, http.StatusBadRequest},
	} {
		r := request(e.ta, "GET", HubPath, "")
		if !tc.tls {
			r.TLS = nil
		}
		for k, v := range tc.header {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != tc.want {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	e.svc.TrustProxyHeaders = true
	r := request(e.ta, "GET", HubPath, "")
	r.TLS = nil
	r.Header.Set("X-Forwarded-Proto", "https")
	if !h.tlsOK(r) {
		t.Fatal("a trusted proxy's X-Forwarded-Proto https proves TLS")
	}
}

// An authenticated socket records a session row and agentIP; a registration
// that evicts its certificate closes it (LR38a-5).
func TestHubSessionsAndEviction(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	srv := hubServer(t, e, h, e.ta)
	k1 := newConnectorKey(t, 2048)
	key := register(t, e, k1)
	c := connect(t, e, srv, k1, key, nil)
	waitFor(t, "session row", func() bool { return len(sessions(t, e, e.conn)) == 1 })
	s := sessions(t, e, e.conn)[0]
	if s.ReplicaID != "replica-a" || s.CertThumbprint == "" || s.AgentIP == "" || !h.Connected("ten_a", e.conn.ID) {
		t.Fatalf("session %+v", s)
	}
	if online, _ := e.svc.Online(context.Background(), e.conn); !online {
		t.Fatal("status offline with a connector")
	}
	got, _ := e.st.Connections().Get(context.Background(), "ten_a", e.conn.ID)
	if got.Extra["agentIP"] != s.AgentIP {
		t.Fatalf("agentIP %v", got.Extra["agentIP"])
	}
	// k2 keeps k1 (two certificates); k3 evicts k1 and closes its socket.
	register(t, e, newConnectorKey(t, 2048))
	if !h.Connected("ten_a", e.conn.ID) {
		t.Fatal("second registration closed the first connector")
	}
	register(t, e, newConnectorKey(t, 2048))
	waitFor(t, "evicted socket closed", func() bool { return !h.Connected("ten_a", e.conn.ID) })
	var raw []byte
	_ = c.ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := websocket.Message.Receive(c.ws, &raw); err == nil {
		t.Fatalf("evicted connector still reads: %s", raw)
	}
	waitFor(t, "session row removed", func() bool { return len(sessions(t, e, e.conn)) == 0 })
}

// A connector that stops sending (no pings) is closed after the idle timeout.
func TestHubIdleTimeout(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	h.idle = 300 * time.Millisecond
	srv := hubServer(t, e, h, e.ta)
	k := newConnectorKey(t, 2048)
	key := register(t, e, k)
	connect(t, e, srv, k, key, nil)
	waitFor(t, "connected", func() bool { return h.Connected("ten_a", e.conn.ID) })
	waitFor(t, "idle socket closed", func() bool { return !h.Connected("ten_a", e.conn.ID) })
}

// The connector pings every 5 s and the hub's pongs share the socket with
// its frames: a write deadline left behind by a frame must not fail a later
// pong (found by make e2e-ad with the real connector).
func TestHubKeepsPingingConnector(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	h.write, h.idle = 100*time.Millisecond, 2*time.Second
	srv := hubServer(t, e, h, e.ta)
	k := newConnectorKey(t, 2048)
	key := register(t, e, k)
	c := connect(t, e, srv, k, key, func(_ string, claims map[string]any) any { return profileReply(claims) })
	waitFor(t, "connected", func() bool { return h.Connected("ten_a", e.conn.ID) })
	if _, err := h.Call(context.Background(), "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "u"}); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		time.Sleep(60 * time.Millisecond) // beyond the last frame's write deadline
		c.writeMu.Lock()
		c.ws.PayloadType = websocket.PingFrame
		_, err := c.ws.Write([]byte("p"))
		c.ws.PayloadType = websocket.TextFrame
		c.writeMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if !h.Connected("ten_a", e.conn.ID) {
		t.Fatal("the hub dropped a pinging connector")
	}
	if _, err := h.Call(context.Background(), "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "u"}); err != nil {
		t.Fatalf("after pings: %v", err)
	}
}
