package adhub

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// replica is a second hub on the same store, as another process would be.
func replica(t *testing.T, e *env, id string) (*Hub, *httptest.Server, *httptest.Server) {
	t.Helper()
	svc := &Service{Store: e.st, Wrapper: e.svc.Wrapper, Now: e.svc.Now}
	h := &Hub{Service: svc, ReplicaID: id}
	svc.Hub = h
	fwd := httptest.NewTLSServer(http.HandlerFunc(h.ServeForward))
	t.Cleanup(fwd.Close)
	h.ReplicaURL = fwd.URL
	return h, hubServer(t, e, h, e.ta), fwd
}

// TestHubForwarding is Review Focus 4: a login on a replica without a
// socket reaches the connector held by another replica.
func TestHubForwarding(t *testing.T) {
	e := newEnv(t)
	a := newHub(e)
	b, bSockets, bForward := replica(t, e, "replica-b")
	a.Forward = a.ForwardOver(bForward.Client())
	k := newConnectorKey(t, 2048)
	key := register(t, e, k)
	c := connect(t, e, bSockets, k, key, func(_ string, claims map[string]any) any { return profileReply(claims) })
	waitFor(t, "session on replica b", func() bool { return b.Connected("ten_a", e.conn.ID) })
	if a.Connected("ten_a", e.conn.ID) {
		t.Fatal("replica a holds no socket")
	}
	ctx := context.Background()
	r, err := e.svc.Authenticate(ctx, e.conn, "jdoe", "pw")
	if err != nil {
		t.Fatalf("forwarded login: %v", err)
	}
	var p struct{ ID string }
	_ = json.Unmarshal(r, &p)
	if p.ID != "jdoe" || len(c.requests()) != 1 || c.requests()[0]["password"] != "pw" {
		t.Fatalf("forwarded reply %s, connector saw %v", r, c.requests())
	}
	// A session row of a replica that is gone is skipped.
	repo, _ := store.ADHub(ctx, e.st)
	_ = repo.PutADHubSession(ctx, &store.ADHubSession{TenantID: "ten_a", ConnectionID: e.conn.ID, SessionID: "ghost", ReplicaID: "replica-gone",
		ReplicaURL: "https://127.0.0.1:1", ConnectedAt: e.now.Add(time.Hour), LastSeenAt: e.now})
	if _, err := e.svc.Authenticate(ctx, e.conn, "jdoe", "pw"); err != nil {
		t.Fatalf("failover past a dead replica: %v", err)
	}
	// The forwarded request is answered from b's own sockets only: without
	// them b says so (409) and a reports the connection unavailable.
	c.ws.Close()
	waitFor(t, "b detached", func() bool { return !b.Connected("ten_a", e.conn.ID) })
	_ = repo.PutADHubSession(ctx, &store.ADHubSession{TenantID: "ten_a", ConnectionID: e.conn.ID, SessionID: "stale", ReplicaID: "replica-b",
		ReplicaURL: b.ReplicaURL, ConnectedAt: e.now, LastSeenAt: e.now})
	if _, err := e.svc.Authenticate(ctx, e.conn, "jdoe", "pw"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no connector anywhere: %v", err)
	}
}

// Forwarding requests must be signed for the connection, fresh, single use
// and over TLS.
func TestForwardAuthentication(t *testing.T) {
	e := newEnv(t)
	register(t, e, newConnectorKey(t, 2048))
	b, _, fwd := replica(t, e, "replica-b")
	key, err := e.svc.SigningKey(context.Background(), "ten_a", e.conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	post := func(fr forwardRequest, sig string, client *http.Client, url string) int {
		body, _ := json.Marshal(fr)
		if sig == "" {
			sig = hex.EncodeToString(forwardMAC(key, body))
		}
		req, _ := http.NewRequest("POST", url+ForwardPath, bytes.NewReader(body))
		req.Header.Set(forwardHeader, sig)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	fresh := func() forwardRequest {
		return forwardRequest{TenantID: "ten_a", ConnectionID: e.conn.ID, Op: OpAuthenticateUser, Claims: map[string]any{"username": "u"},
			Time: e.now.Unix(), Nonce: hex.EncodeToString(bytes.Repeat([]byte{byte(time.Now().UnixNano())}, 16))}
	}
	ok := fresh()
	if code := post(ok, "", fwd.Client(), fwd.URL); code != http.StatusConflict {
		t.Fatalf("valid request without a socket on b: %d", code)
	}
	if code := post(ok, "", fwd.Client(), fwd.URL); code != http.StatusUnauthorized {
		t.Fatalf("replayed request: %d", code)
	}
	stale := fresh()
	stale.Nonce = hex.EncodeToString(bytes.Repeat([]byte{7}, 16))
	stale.Time = e.now.Add(-2 * time.Minute).Unix()
	if code := post(stale, "", fwd.Client(), fwd.URL); code != http.StatusUnauthorized {
		t.Fatalf("stale request: %d", code)
	}
	forged := fresh()
	forged.Nonce = hex.EncodeToString(bytes.Repeat([]byte{8}, 16))
	if code := post(forged, hex.EncodeToString(forwardMAC([]byte("guess"), []byte("x"))), fwd.Client(), fwd.URL); code != http.StatusUnauthorized {
		t.Fatalf("forged signature: %d", code)
	}
	// The other tenant's connection key does not sign for this one.
	other := fresh()
	other.Nonce = hex.EncodeToString(bytes.Repeat([]byte{9}, 16))
	other.TenantID, other.ConnectionID = "ten_b", e.connB.ID
	if code := post(other, "", fwd.Client(), fwd.URL); code != http.StatusUnauthorized {
		t.Fatalf("cross-connection signature: %d", code)
	}
	plain := httptest.NewServer(http.HandlerFunc(b.ServeForward))
	defer plain.Close()
	p := fresh()
	p.Nonce = hex.EncodeToString(bytes.Repeat([]byte{10}, 16))
	if code := post(p, "", plain.Client(), plain.URL); code != http.StatusForbidden {
		t.Fatalf("plain HTTP: %d", code)
	}
}
