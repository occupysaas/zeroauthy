package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/cimd"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const cimdSeed = `
tenants:
  - name: cimd
    domains: [cimd.example.test]
    settings:
      client_id_metadata_document_supported: true
      client_id_metadata_document_dynamic_registration_supported: true
`

type cimdServer struct {
	h    http.Handler
	st   store.Store
	tn   *store.Tenant
	docs *httptest.Server
	key  *rsa.PrivateKey
}

func newCIMDServer(t *testing.T) *cimdServer {
	t.Helper()
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/public.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "https://" + r.Host + r.URL.Path, "client_name": "Public agent", "redirect_uris": []string{"https://agent.example/cb"}})
	})
	mux.HandleFunc("/signed.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "https://" + r.Host + r.URL.Path, "redirect_uris": []string{"https://agent.example/cb"},
			"token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{jose.JSONWebKey{Key: &key.PublicKey, KeyID: "agent-key", Algorithm: "RS256", Use: "sig"}}}})
	})
	docs := httptest.NewTLSServer(mux)
	t.Cleanup(docs.Close)
	st := memory.New()
	f, err := seed.Parse([]byte(cimdSeed))
	if err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err := seed.Apply(ctx, st, f, nil, w); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	tn, _ := st.Tenants().GetByName(ctx, "cimd")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	pool := docs.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	h := contract.Wrap(t, New(Deps{
		Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Sessions: &session.Manager{Store: st}, Mailer: discardMailer{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		CIMD: &cimd.Registrar{Store: st, Fetcher: cimd.NewFetcher(federation.FixturePolicy(pool))},
	}))
	return &cimdServer{h: h, st: st, tn: tn, docs: docs, key: key}
}

func (s *cimdServer) clients(t *testing.T) []*store.Client {
	cs, _, err := s.st.Clients().List(context.Background(), s.tn.ID, store.ClientFilter{}, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// A Client ID Metadata Document URL is a client_id at /authorize: the
// tenant registers it on first use, and its redirect_uris are the only
// callbacks.
func TestCIMDAuthorizeThroughServer(t *testing.T) {
	s := newCIMDServer(t)
	clientID := s.docs.URL + "/public.json"
	q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://agent.example/cb"}, "response_type": {"code"},
		"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}, "scope": {"openid"}}
	rec := get(s.h, "https://cimd.example.test/authorize?"+q.Encode())
	if strings.Contains(rec.Body.String(), "unknown client") {
		t.Fatalf("CIMD client not resolved: %d %s", rec.Code, rec.Body)
	}
	cs := s.clients(t)
	if len(cs) != 1 || cs[0].ExternalClientID() != clientID || cs[0].External.CreatedBy != store.ExternalCreatedByClient {
		t.Fatalf("clients %+v", cs)
	}
	// Another callback is refused as for any client.
	q.Set("redirect_uri", "https://evil.example/cb")
	rec = get(s.h, "https://cimd.example.test/authorize?"+q.Encode())
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("foreign callback: %d %v", rec.Code, rec.Header())
	}
	// A URL whose document cannot be fetched is invalid_client.
	q.Set("client_id", s.docs.URL+"/missing.json")
	q.Set("redirect_uri", "https://agent.example/cb")
	rec = get(s.h, "https://cimd.example.test/authorize?"+q.Encode())
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "client metadata document is unavailable") || len(s.clients(t)) != 1 {
		t.Fatalf("unreachable document: %d %s", rec.Code, rec.Body)
	}
}

func (s *cimdServer) assertion(t *testing.T, iss string, key *rsa.PrivateKey) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "agent-key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: iss, Subject: iss, Audience: jwt.Audience{"https://cimd.example.test/"},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)), ID: strings.Repeat("j", 8) + now.Format("150405.000000000")}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (s *cimdServer) token(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://cimd.example.test/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	return w
}

// At /oauth/token a CIMD client authenticates with private_key_jwt whose
// iss and sub are its URL, using the document's keys.
func TestCIMDTokenAssertionThroughServer(t *testing.T) {
	s := newCIMDServer(t)
	clientID := s.docs.URL + "/signed.json"
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-code"}, "redirect_uri": {"https://agent.example/cb"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {s.assertion(t, clientID, s.key)}}
	rec := s.token(t, form)
	if !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("authenticated client should reach the grant: %d %s", rec.Code, rec.Body)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	form.Set("client_assertion", s.assertion(t, clientID, other))
	if rec := s.token(t, form); rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("wrong key: %d %s", rec.Code, rec.Body)
	}
}
