package adhub

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/net/websocket"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// hubServer serves the hub of e on a TLS test server for tenant tn.
func hubServer(t *testing.T, e *env, h *Hub, tn *store.Tenant) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: tn.CanonicalHost}))
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeConnector speaks the connector's side of the protocol
// (ws_validator.js) for tests.
type fakeConnector struct {
	t          *testing.T
	ws         *websocket.Conn
	signingKey string
	writeMu    sync.Mutex
	mu         sync.Mutex
	got        []map[string]any
	// answer builds the reply payload of a request; nil means no reply.
	answer func(op string, claims map[string]any) any
}

func dialHub(t *testing.T, srv *httptest.Server) (*websocket.Conn, error) {
	t.Helper()
	cfg, err := websocket.NewConfig(strings.Replace(srv.URL, "https", "wss", 1)+HubPath, "https://ignored.example")
	if err != nil {
		return nil, err
	}
	cfg.Header = http.Header{}                            // no Origin, as the connector
	cfg.TlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server
	return websocket.DialConfig(cfg)
}

// hubToken is the connector's authenticate JWT (ws_validator.js 347–358).
func hubToken(t *testing.T, k connectorKey, iss, aud string, exp time.Time, jti ...string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{Issuer: iss, Audience: jwt.Audience{aud}, Expiry: jwt.NewNumericDate(exp), IssuedAt: jwt.NewNumericDate(exp.Add(-time.Minute))}
	if len(jti) > 0 {
		claims.ID = jti[0]
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// authenticateRaw sends the authenticate message and returns the hub's answer.
func authenticateRaw(t *testing.T, ws *websocket.Conn, token string) string {
	t.Helper()
	p, _ := json.Marshal(tokenPayload{JWT: token})
	b, _ := json.Marshal(frame{N: evAuthenticate, P: p})
	if _, err := ws.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var raw []byte
	if err := websocket.Message.Receive(ws, &raw); err != nil {
		return "closed"
	}
	var f frame
	_ = json.Unmarshal(raw, &f)
	return f.N
}

// connect dials, authenticates and starts answering requests.
func connect(t *testing.T, e *env, srv *httptest.Server, k connectorKey, signingKey string, answer func(string, map[string]any) any) *fakeConnector {
	t.Helper()
	ws, err := dialHub(t, srv)
	if err != nil {
		t.Fatal(err)
	}
	if got := authenticateRaw(t, ws, hubToken(t, k, "corp", "urn:auth0:acme:corp", e.now.Add(time.Minute), fmt.Sprint(connectSeq.Add(1)))); got != evAuthenticated {
		t.Fatalf("authenticate: %s", got)
	}
	_ = ws.SetReadDeadline(time.Time{})
	c := &fakeConnector{t: t, ws: ws, signingKey: signingKey, answer: answer}
	go c.loop()
	t.Cleanup(func() { ws.Close() })
	return c
}

func (c *fakeConnector) loop() {
	for {
		var raw []byte
		if err := websocket.Message.Receive(c.ws, &raw); err != nil {
			return
		}
		var f frame
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		var p tokenPayload
		_ = json.Unmarshal(f.P, &p)
		tok, err := jwt.ParseSigned(p.JWT, []jose.SignatureAlgorithm{jose.HS256})
		if err != nil {
			continue
		}
		claims := map[string]any{}
		// The connector drops requests whose token it cannot verify.
		if tok.Claims([]byte(c.signingKey), &claims) != nil {
			continue
		}
		c.mu.Lock()
		c.got = append(c.got, claims)
		c.mu.Unlock()
		if c.answer == nil {
			continue
		}
		reply := c.answer(f.N, claims)
		if reply == nil {
			continue
		}
		pid, _ := claims["pid"].(string)
		body, _ := json.Marshal(reply)
		b, _ := json.Marshal(frame{N: pid + Op(f.N).replySuffix(), P: body})
		c.writeMu.Lock()
		_, _ = c.ws.Write(b)
		c.writeMu.Unlock()
	}
}

func (c *fakeConnector) requests() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.got...)
}

// register posts k through e's ticket and returns the signing key.
func register(t *testing.T, e *env, k connectorKey) string {
	t.Helper()
	rec := configure(t, e, e.ticket(e.ta, e.conn), `{"certs":["`+k.b64()+`"],"signInEndpoint":"http://connector.corp:4000/wsfed","agentMode":true,"agentVersion":"8.0.5"}`)
	var out struct{ SigningKey string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	return out.SigningKey
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sessions(t *testing.T, e *env, conn *store.Connection) []*store.ADHubSession {
	t.Helper()
	repo, _ := store.ADHub(context.Background(), e.st)
	list, err := repo.ListADHubSessions(context.Background(), conn.TenantID, conn.ID, e.now.Add(-SessionLiveness))
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// connectSeq makes each test connection's token distinct (tokens are
// single use; the real connector signs a new one per connection).
var connectSeq atomic.Int64

var errNoReply = errors.New("no reply")
