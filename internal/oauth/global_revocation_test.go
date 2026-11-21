package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type globalFixture struct {
	h      *Handlers
	st     store.Store
	issuer string
	key    *rsa.PrivateKey
	now    time.Time
	tn     *store.Tenant
}

func newGlobalFixture(t *testing.T) *globalFixture {
	t.Helper()
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "upstream", Use: "sig", Algorithm: "RS256"}}})
	}))
	t.Cleanup(idp.Close)
	f := &globalFixture{st: st, issuer: "https://example.com", key: key, now: time.Now().UTC().Truncate(time.Second), tn: &store.Tenant{ID: "t", Name: "t", CanonicalHost: "tenant.example", Domains: []string{"tenant.example"}}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Tenants().Create(t.Context(), f.tn))
	spec := connrules.Spec{Name: "Enterprise", Strategy: "oidc", Options: connrules.Options{Extra: map[string]any{"type": "front_channel", "client_id": "integration", "scope": "openid", "issuer": f.issuer, "authorization_endpoint": f.issuer + "/authorize", "jwks_uri": f.issuer + "/jwks"}}}
	conn := &store.Connection{TenantID: "t", ID: "enterprise", FederationRevision: 1}
	connrules.Apply(&spec, conn)
	must(st.Connections().Create(t.Context(), conn))
	cfg, err := federation.ParseConfig(*connrules.FromConnection(conn))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != f.issuer {
		t.Fatalf("unbound fixture issuer")
	}
	must(st.Users().Create(t.Context(), &store.User{TenantID: "t", UserID: "auth0|owner", Email: "owner@example.test", Identities: []store.Identity{{Connection: "DB", Provider: "auth0", UserID: "owner"}, {Connection: "Enterprise", Provider: "oidc", UserID: "Enterprise|upstream-user", ProfileData: map[string]any{"email": "linked@example.test"}}}}))
	must(st.Clients().Create(t.Context(), &store.Client{TenantID: "t", ClientID: "rp", OIDCLogout: &store.OIDCLogout{BackchannelURLs: []string{"https://rp.example/logout"}}}))
	must(st.Sessions().Create(t.Context(), &store.LoginSession{TenantID: "t", ID: "sid", UserID: "auth0|owner", TokenHash: "session-hash", ClientIDs: []string{"rp"}, ExpiresAt: f.now.Add(time.Hour), IdleExpiresAt: f.now.Add(time.Hour)}))
	must(st.RefreshTokens().Create(t.Context(), &store.RefreshToken{TenantID: "t", ID: "rt", TokenHash: "refresh-hash", UserID: "auth0|owner", ClientID: "rp", FamilyID: "family", ExpiresAt: f.now.Add(time.Hour)}))
	wrapper, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	km := keys.NewManager(st.SigningKeys(), wrapper)
	must(km.Ensure(t.Context(), "t"))
	roots := x509.NewCertPool()
	roots.AddCert(idp.Certificate())
	f.h = &Handlers{Store: st, Now: func() time.Time { return f.now }, Federation: &federation.FlowService{Providers: federation.NewProviders(federation.NetworkPolicy{RootCAs: roots, Resolver: globalResolver{}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, idp.Listener.Addr().String())
	}}, func() time.Time { return f.now })}, Logout: &logout.Service{Store: st, Wrapper: wrapper, Keys: km, Now: func() time.Time { return f.now }}}
	return f
}
func (f *globalFixture) jwt(t *testing.T, change func(map[string]any)) string {
	c := map[string]any{"iss": f.issuer, "sub": "integration", "aud": "https://tenant.example/oauth/global-token-revocation/connection/Enterprise", "iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(), "jti": secrets.RandomString(24)}
	if change != nil {
		change(c)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithType("global-token-revocation+jwt").WithHeader("kid", "upstream"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(c)
	obj, _ := signer.Sign(payload)
	raw, _ := obj.CompactSerialize()
	return raw
}
func (f *globalFixture) call(t *testing.T, name, token, body string) int {
	r := httptest.NewRequest(http.MethodPost, "https://tenant.example/oauth/global-token-revocation/connection/"+name, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: f.tn, Host: "tenant.example"}))
	w := httptest.NewRecorder()
	f.h.GlobalTokenRevocation(w, r, name)
	return w.Code
}
func (f *globalFixture) body() string {
	raw, _ := json.Marshal(map[string]any{"sub_id": map[string]any{"format": "iss_sub", "iss": f.issuer, "sub": "upstream-user"}})
	return string(raw)
}
func TestGlobalRevocationSuccess(t *testing.T) {
	f := newGlobalFixture(t)
	raw := f.jwt(t, nil)
	if status := f.call(t, "Enterprise", raw, f.body()); status != 204 {
		t.Fatalf("status %d", status)
	}
	if _, err := f.st.Sessions().Get(t.Context(), "t", "sid"); err != store.ErrNotFound {
		t.Fatal("session survived")
	}
	rt, err := f.st.RefreshTokens().GetByTokenHash(t.Context(), "t", "refresh-hash")
	if err != nil || rt.RevokedAt == nil {
		t.Fatal("refresh survived")
	}
	jobs, err := f.st.Actions().ClaimJobs(t.Context(), f.now, time.Minute, 10)
	if err != nil || len(jobs) != 1 || jobs[0].Trigger != logout.JobKind {
		t.Fatalf("logout not enqueued %d %v", len(jobs), err)
	}
	sealed, err := keys.OpenBound(f.h.Logout.Wrapper, "backchannel-logout/v1", []string{"t", jobs[0].ID, logout.JobKind}, jobs[0].Sealed)
	var snapshot struct{ Initiator string }
	if err != nil || json.Unmarshal(sealed, &snapshot) != nil || snapshot.Initiator != "idp-logout" {
		t.Fatal("wrong logout initiator")
	}
	if status := f.call(t, "Enterprise", raw, f.body()); status != 401 {
		t.Fatalf("replay %d", status)
	}
}
func TestGlobalRevocationUnknownSubject(t *testing.T) {
	f := newGlobalFixture(t)
	body := strings.ReplaceAll(f.body(), "upstream-user", "missing")
	if status := f.call(t, "Enterprise", f.jwt(t, nil), body); status != 204 {
		t.Fatalf("status %d", status)
	}
	if _, err := f.st.Sessions().Get(t.Context(), "t", "sid"); err != nil {
		t.Fatal("unrelated session changed")
	}
}
func TestGlobalRevocationConnection(t *testing.T) {
	f := newGlobalFixture(t)
	if err := f.st.Connections().Create(t.Context(), &store.Connection{TenantID: "t", ID: "social", Name: "Google", Strategy: "google-oauth2"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "Google"} {
		if got := f.call(t, name, f.jwt(t, nil), f.body()); got != 404 {
			t.Fatalf("%s: %d", name, got)
		}
	}
	for _, body := range []string{`{}`, `[]`, `{"sub_id":{"format":"iss_sub","sub":"x"}}`, `{"sub_id":{"format":"email","email":42}}`, `{"sub_id":{"format":"email","email":"x"}} trailing`} {
		if got := f.call(t, "Enterprise", f.jwt(t, nil), body); got != 400 {
			t.Fatalf("malformed status %d", got)
		}
	}
}
func TestGlobalRevocationNoUserLookupByEmail(t *testing.T) {
	for _, email := range []string{"linked@example.test", "owner@example.test"} {
		t.Run(email, func(t *testing.T) {
			f := newGlobalFixture(t)
			body := `{"sub_id":{"format":"email","email":"` + email + `"}}`
			if got := f.call(t, "Enterprise", f.jwt(t, nil), body); got != 204 {
				t.Fatalf("status %d", got)
			}
			_, err := f.st.Sessions().Get(t.Context(), "t", "sid")
			if email == "linked@example.test" && err != store.ErrNotFound {
				t.Fatal("linked email unresolved")
			}
			if email == "owner@example.test" && err != nil {
				t.Fatal("root email selected wrong identity")
			}
		})
	}
}
func TestGlobalRevocationRefusals(t *testing.T) {
	f := newGlobalFixture(t)
	for _, change := range []func(map[string]any){func(c map[string]any) { c["iss"] = "https://other.example/" }, func(c map[string]any) { c["aud"] = "https://other.example/" }, func(c map[string]any) { c["exp"] = f.now.Add(-time.Second).Unix() }, func(c map[string]any) { c["exp"] = f.now.Add(301 * time.Second).Unix() }} {
		if got := f.call(t, "Enterprise", f.jwt(t, change), f.body()); got != 401 {
			t.Fatalf("refusal status %d", got)
		}
	}
	if got := f.call(t, "Enterprise", "eyJhbGciOiJub25lIn0.e30.", f.body()); got != 401 {
		t.Fatalf("unsigned %d", got)
	}
	if _, err := f.st.Sessions().Get(context.Background(), "t", "sid"); err != nil {
		t.Fatal("invalid request changed state")
	}
}

type globalResolver struct{}

func (globalResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func TestGlobalRevocationOutcomeLogs(t *testing.T) {
	f := newGlobalFixture(t)
	capture := &eventRecorder{}
	f.h.Recorder = capture
	raw := f.jwt(t, nil)
	if f.call(t, "Enterprise", raw, f.body()) != 204 || f.call(t, "Enterprise", raw, f.body()) != 401 {
		t.Fatal("unexpected outcome")
	}
	if len(capture.events) != 2 || capture.events[0].Type != "universal_logout_succeeded" || capture.events[1].Type != "universal_logout_failed" {
		t.Fatal("missing terminal outcome logs")
	}
	encoded, _ := json.Marshal(capture.events)
	for _, private := range []string{raw, "upstream-user", "linked@example.test", "owner@example.test"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("outcome log contains private data")
		}
	}
}
