package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestSocialStandIn runs zeroauthy's descriptor provider against the
// stand-in for every Plan 39b strategy: authorize, the code exchange and
// the profile, so the E2E lane fails here first when the two drift.
func TestSocialStandIn(t *testing.T) {
	var p *Provider
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) }))
	defer srv.Close()
	p, _ = New(srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ps := federation.NewProviders(federation.FixturePolicy(pool), nil).WithSocialFixture(srv.URL + "/social")
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, d := range providers.All() {
		t.Run(d.Strategy, func(t *testing.T) {
			if d.Retired != nil {
				t.Skip("retired: TestRetiredProviders")
			}
			if d.Protocol == providers.ProtocolOAuth1 {
				t.Skip("OAuth 1.0a descriptors: TestSocialStandInOAuth1")
			}
			opts := map[string]any{"client_id": ClientID, "client_secret": ClientSecret}
			if len(d.BaseURLHosts) > 0 {
				opts["baseUrl"] = "https://" + d.BaseURLHosts[0]
			}
			if d.Strategy == "salesforce-community" {
				opts["community_base_url"] = "https://community.example"
			}
			if _, ok := d.Flag("email"); ok {
				opts["email"] = true
			}
			raw, _ := json.Marshal(map[string]any{"name": "c", "strategy": d.Strategy, "options": opts})
			var spec connrules.Spec
			if err := json.Unmarshal(raw, &spec); err != nil {
				t.Fatal(err)
			}
			cfg, err := federation.ParseConfig(spec)
			if err != nil {
				t.Fatal(err)
			}
			e, err := ps.SocialEndpoints(cfg, "my-shop")
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte("verifier-1"))
			auth, err := ps.For(cfg).AuthorizationURL(federation.StartInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				State: "state-1", CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:])})
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Get(auth)
			if err != nil || res.StatusCode != 200 {
				t.Fatalf("authorize %v %v", res.StatusCode, err)
			}
			res.Body.Close()
			u, _ := url.Parse(auth)
			q := u.Query()
			post := url.Values{"subject": {"user-1"}, "decision": {"allow"}, "redirect_uri": {q.Get(redirectParamOf(d))}, "state": {q.Get("state")}, "code_challenge": {q.Get("code_challenge")}}
			res, err = client.PostForm(u.Scheme+"://"+u.Host+u.Path, post)
			if err != nil || res.StatusCode != http.StatusFound {
				t.Fatalf("allow %v %v", res.StatusCode, err)
			}
			loc, _ := url.Parse(res.Header.Get("Location"))
			result, err := ps.For(cfg).Exchange(context.Background(), federation.ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
				Code: loc.Query().Get("code"), CodeVerifier: "verifier-1", ClientSecret: ClientSecret})
			if err != nil {
				t.Fatal(err)
			}
			if result.Profile.Subject != "user-1" {
				t.Fatalf("subject %q", result.Profile.Subject)
			}
			wantEmail := d.Profile.Email != "" || d.Hook == providers.HookLine
			if wantEmail != (result.Profile.Email != nil) || wantEmail && *result.Profile.Email != SocialEmail(d.Strategy, "user-1") {
				t.Fatalf("email %v", result.Profile.Email)
			}
			if wantEmail && *result.Profile.EmailVerified != (d.EmailVerified.Rule != providers.EmailNever) {
				t.Fatalf("email_verified %v (rule %s)", *result.Profile.EmailVerified, d.EmailVerified.Rule)
			}
		})
	}
}

// TestSocialStandInOAuth1 drives zeroauthy's OAuth 1.0a flow against the
// Evernote stand-ins.
func TestSocialStandInOAuth1(t *testing.T) {
	var p *Provider
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { p.ServeHTTP(w, r) }))
	defer srv.Close()
	p, _ = New(srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, strategy := range []string{"evernote", "evernote-sandbox"} {
		t.Run(strategy, func(t *testing.T) {
			env := newOAuth1Env(t, strategy, federation.NewProviders(federation.FixturePolicy(pool), nil).WithSocialFixture(srv.URL+"/social"))
			begun := env.begin(t)
			res, err := client.Get(begun.URL)
			if err != nil || res.StatusCode != 200 {
				t.Fatalf("authorize %v %v", res, err)
			}
			res.Body.Close()
			u, _ := url.Parse(begun.URL)
			res, err = client.PostForm(u.Scheme+"://"+u.Host+u.Path, url.Values{"subject": {"77"}, "decision": {"allow"}, "oauth_token": {u.Query().Get("oauth_token")}, "callback": {"https://login.example/login/callback"}})
			if err != nil || res.StatusCode != http.StatusFound {
				t.Fatalf("allow %v %v", res, err)
			}
			cb, _ := url.Parse(res.Header.Get("Location"))
			done, err := env.complete(t, begun, cb.RawQuery)
			if err != nil || done.UserID != strategy+"|77" {
				t.Fatalf("login %+v %v", done, err)
			}
		})
	}
}

type oauth1Env struct {
	ctx  context.Context
	st   *memory.Store
	svc  *federation.FlowService
	conn *store.Connection
}

func newOAuth1Env(t *testing.T, strategy string, ps *federation.Providers) *oauth1Env {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	_ = st.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten"})
	_ = st.Clients().Create(ctx, &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true, GrantTypes: []string{"authorization_code"}})
	spec := connrules.Spec{Name: strategy, Strategy: strategy, EnabledClients: []string{"client"}, Options: connrules.Options{Extra: map[string]any{"client_id": ClientID}}}
	c := &store.Connection{TenantID: "ten", ID: "con_" + strategy, FederationRevision: 1}
	connrules.Apply(&spec, c)
	c.FederationSecretsSealed, _ = federation.SealCredentials(w, "ten", c.ID, federation.Credentials{ClientSecret: ClientSecret})
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	return &oauth1Env{ctx: ctx, st: st, conn: c, svc: &federation.FlowService{Service: federation.Service{Wrapper: w}, Store: st, Providers: ps}}
}

func (e *oauth1Env) begin(t *testing.T) *federation.Begun {
	t.Helper()
	txn := &store.AuthTransaction{ID: "txn", TenantID: "ten", ClientID: "client", ExpiresAt: time.Now().Add(time.Hour)}
	_ = e.st.AuthTransactions().Create(e.ctx, txn)
	b, err := e.svc.Begin(e.ctx, federation.BeginInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Txn: txn,
		Client: &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true}, Connection: e.conn})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *oauth1Env) complete(t *testing.T, b *federation.Begun, query string) (*federation.Completion, error) {
	t.Helper()
	p, err := federation.ParseCallback(query)
	if err != nil {
		return nil, err
	}
	return e.svc.Complete(e.ctx, federation.CompleteInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Params: p, CookieValue: b.CookieValue})
}
