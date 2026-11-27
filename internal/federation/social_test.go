package federation

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const (
	socTestToken  = "throwaway-social-access-token"
	socTestSecret = "throwaway-social-client-secret"
)

// socFixture is a local TLS stand-in for every descriptor provider: the
// descriptor URLs are rewritten to <srv>/<strategy><path>.
type socFixture struct {
	srv      *httptest.Server
	mu       sync.Mutex
	handlers map[string]func(http.ResponseWriter, *http.Request) // by path
	forms    map[string]url.Values
	headers  map[string]http.Header
	queries  map[string]string
	calls    map[string]int
}

func newSocFixture(t *testing.T) *socFixture {
	t.Helper()
	f := &socFixture{handlers: map[string]func(http.ResponseWriter, *http.Request){},
		forms: map[string]url.Values{}, headers: map[string]http.Header{}, queries: map[string]string{}, calls: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		_ = r.ParseForm()
		f.forms[r.URL.Path] = r.PostForm
		f.headers[r.URL.Path] = r.Header.Clone()
		f.queries[r.URL.Path] = r.URL.RawQuery
		f.calls[r.URL.Path]++
		h, ok := f.handlers[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			jsonHandler(404, `{}`)(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *socFixture) on(path string, h func(http.ResponseWriter, *http.Request)) {
	f.mu.Lock()
	f.handlers[path] = h
	f.mu.Unlock()
}

func (f *socFixture) providers() *Providers {
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	return NewProviders(FixturePolicy(pool), func() time.Time { return fixedTime }).WithSocialFixture(f.srv.URL)
}

func socConfig(t *testing.T, strategy, extra string) Config {
	t.Helper()
	cfg, err := ParseConfig(configSpec(t, strategy, `{"client_id":"throwaway-client","client_secret":"`+socTestSecret+`"`+extra+`}`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (f *socFixture) exchange(t *testing.T, ps *Providers, cfg Config) (ProviderResult, error) {
	t.Helper()
	e, err := ps.SocialEndpoints(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	return ps.For(cfg).Exchange(context.Background(), ExchangeInput{Config: cfg, Endpoints: e,
		CallbackURL: "https://login.example/login/callback", Code: "code-1", CodeVerifier: "verifier-1",
		ClientSecret: socTestSecret, Now: fixedTime})
}

func socNoSecrets(t *testing.T, err error, extra ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range append([]string{socTestToken, socTestSecret, "code-1"}, extra...) {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error %q leaks %q", err, s)
		}
	}
}

const amazonProfile = `{"user_id":"amzn1.account.THROWAWAY","name":"Test Shopper","email":"shopper@example.com","postal_code":"98109"}`

func amazonFixture(t *testing.T) *socFixture {
	f := newSocFixture(t)
	f.on("/amazon/auth/o2/token", jsonHandler(200, `{"access_token":"`+socTestToken+`","token_type":"bearer","expires_in":3600,"refresh_token":"throwaway-refresh"}`))
	f.on("/amazon/user/profile", jsonHandler(200, amazonProfile))
	return f
}

func TestSocialAuthorizationURL(t *testing.T) {
	cfg := socConfig(t, "amazon", `,"postal_code":true`)
	ps := NewProviders(NetworkPolicy{}, nil)
	e, err := ps.SocialEndpoints(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.AuthorizationURL != "https://www.amazon.com/ap/oa" || e.TokenURL != "https://api.amazon.com/auth/o2/token" ||
		e.UserInfoURL != "https://api.amazon.com/user/profile" || e.TokenAuthMethod != authPost || e.PKCEMethod != "S256" {
		t.Fatalf("endpoints %+v", e)
	}
	raw, err := ps.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		State: "state-1", Nonce: "nonce-1", CodeChallenge: "challenge-1", LoginHint: "someone@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Host != "www.amazon.com" || u.Path != "/ap/oa" || q.Get("response_type") != "code" || q.Get("client_id") != "throwaway-client" ||
		q.Get("redirect_uri") != "https://login.example/login/callback" || q.Get("scope") != "profile postal_code" ||
		q.Get("state") != "state-1" || q.Get("code_challenge") != "challenge-1" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL %s", raw)
	}
	for _, k := range []string{"nonce", "login_hint", "client_secret"} {
		if q.Has(k) {
			t.Fatalf("authorize URL carries %s: %s", k, raw)
		}
	}
}

func TestSocialExchangeAndProfile(t *testing.T) {
	f := amazonFixture(t)
	cfg := socConfig(t, "amazon", "")
	res, err := f.exchange(t, f.providers(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	form := f.forms["/amazon/auth/o2/token"]
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" || form.Get("code_verifier") != "verifier-1" ||
		form.Get("client_id") != "throwaway-client" || form.Get("client_secret") != socTestSecret || form.Get("redirect_uri") != "https://login.example/login/callback" {
		t.Fatalf("token form %v", form)
	}
	if got := f.headers["/amazon/user/profile"].Get("Authorization"); got != "Bearer "+socTestToken {
		t.Fatalf("profile auth %q", got)
	}
	p := res.Profile
	if p.Subject != "amzn1.account.THROWAWAY" || p.Email == nil || *p.Email != "shopper@example.com" ||
		p.EmailVerified == nil || *p.EmailVerified || p.Name == nil || *p.Name != "Test Shopper" || p.ProviderData["postal_code"] != "98109" {
		t.Fatalf("profile %+v", p)
	}
	if res.Tokens.AccessToken != socTestToken || res.Tokens.RefreshToken != "throwaway-refresh" || res.Tokens.ExpiresAt != fixedTime.Add(time.Hour) {
		t.Fatalf("tokens %+v", res.Tokens)
	}
}

func TestSocialSubjects(t *testing.T) {
	for name, c := range map[string]struct {
		body, want string
	}{
		"integer":       {`{"user_id":12345678901234567890}`, "12345678901234567890"},
		"string":        {`{"user_id":"abc"}`, "abc"},
		"fraction":      {`{"user_id":1.5}`, ""},
		"missing":       {`{"name":"x"}`, ""},
		"empty":         {`{"user_id":""}`, ""},
		"control":       {`{"user_id":"a\u0000b"}`, ""},
		"object":        {`{"user_id":{"a":1}}`, ""},
		"too long":      {`{"user_id":"` + strings.Repeat("a", 1100) + `"}`, ""},
		"not an object": {`[1]`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := amazonFixture(t)
			f.on("/amazon/user/profile", jsonHandler(200, c.body))
			res, err := f.exchange(t, f.providers(), socConfig(t, "amazon", ""))
			if c.want == "" {
				if err == nil {
					t.Fatalf("accepted subject %q", res.Profile.Subject)
				}
				socNoSecrets(t, err)
				return
			}
			if err != nil || res.Profile.Subject != c.want {
				t.Fatalf("subject %q, %v", res.Profile.Subject, err)
			}
		})
	}
}

func TestSocialProviderErrors(t *testing.T) {
	for name, set := range map[string]func(*socFixture){
		"token status": func(f *socFixture) {
			f.on("/amazon/auth/o2/token", jsonHandler(400, `{"error":"invalid_grant","error_description":"`+socTestSecret+`"}`))
		},
		"token error": func(f *socFixture) { f.on("/amazon/auth/o2/token", jsonHandler(200, `{"error":"invalid_grant"}`)) },
		"no token type": func(f *socFixture) {
			f.on("/amazon/auth/o2/token", jsonHandler(200, `{"access_token":"`+socTestToken+`"}`))
		},
		"mac token type": func(f *socFixture) {
			f.on("/amazon/auth/o2/token", jsonHandler(200, `{"access_token":"`+socTestToken+`","token_type":"mac"}`))
		},
		"profile status":  func(f *socFixture) { f.on("/amazon/user/profile", jsonHandler(401, `{"error":"`+socTestToken+`"}`)) },
		"profile garbage": func(f *socFixture) { f.on("/amazon/user/profile", jsonHandler(200, `not json `+socTestToken)) },
		"profile redirect": func(f *socFixture) {
			f.on("/amazon/user/profile", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://evil.example/", http.StatusFound)
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := amazonFixture(t)
			set(f)
			_, err := f.exchange(t, f.providers(), socConfig(t, "amazon", ""))
			if !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("err %v", err)
			}
			socNoSecrets(t, err)
		})
	}
}

// TestSocialPKCENone runs a descriptor that does not use PKCE: no challenge
// upstream and no verifier at the token endpoint.
func TestSocialPKCENone(t *testing.T) {
	d, _ := providers.Get("amazon")
	d.PKCE = providers.PKCENone
	d.TokenAuth = providers.AuthBasic
	f := amazonFixture(t)
	ps := f.providers()
	cfg := socConfig(t, "amazon", "")
	p := socialProvider{ps: ps, d: d}
	e, err := ps.socialEndpoints(p.d, cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if e.PKCEMethod != "" || e.TokenAuthMethod != authBasic {
		t.Fatalf("endpoints %+v", e)
	}
	raw, err := p.AuthorizationURL(StartInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback", State: "s", CodeChallenge: "c"})
	if err != nil || strings.Contains(raw, "code_challenge") {
		t.Fatalf("authorize %s %v", raw, err)
	}
	if _, err := p.Exchange(context.Background(), ExchangeInput{Config: cfg, Endpoints: e, CallbackURL: "https://login.example/login/callback",
		Code: "code-1", CodeVerifier: "verifier-1", ClientSecret: socTestSecret, Now: fixedTime}); err != nil {
		t.Fatal(err)
	}
	form := f.forms["/amazon/auth/o2/token"]
	if form.Has("code_verifier") || form.Has("client_secret") {
		t.Fatalf("token form %v", form)
	}
	if user, pass, ok := (&http.Request{Header: f.headers["/amazon/auth/o2/token"]}).BasicAuth(); !ok || user != "throwaway-client" || pass != socTestSecret {
		t.Fatalf("basic auth %q %q %v", user, pass, ok)
	}
}

func TestSocialHooksRegistered(t *testing.T) {
	for _, d := range providers.All() {
		if d.Hook == "" {
			continue
		}
		if _, ok := socialHooks[d.Hook]; !ok {
			t.Fatalf("%s: hook %q has no implementation", d.Strategy, d.Hook)
		}
	}
}

// socFlowEnv drives FlowService Begin and Complete for one descriptor
// connection against the fixture.
type socFlowEnv struct {
	ctx  context.Context
	st   *memory.Store
	svc  *FlowService
	conn *store.Connection
	n    int
}

func newSocFlowEnv(t *testing.T, f *socFixture, strategy string, options map[string]any) *socFlowEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{4}, 32))
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Clients().Create(ctx, &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true, GrantTypes: []string{"authorization_code"}}); err != nil {
		t.Fatal(err)
	}
	extra := map[string]any{"client_id": "throwaway-client"}
	maps.Copy(extra, options)
	spec := connrules.Spec{Name: strategy + "-conn", Strategy: strategy, EnabledClients: []string{"client"}, Options: connrules.Options{Extra: extra}}
	c := &store.Connection{TenantID: "ten", ID: "con_" + strategy, FederationRevision: 1}
	connrules.Apply(&spec, c)
	c.FederationSecretsSealed, _ = SealCredentials(w, "ten", c.ID, Credentials{ClientSecret: socTestSecret})
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	svc := &FlowService{Service: Service{Wrapper: w, Now: func() time.Time { return fixedTime }}, Store: st, Providers: f.providers()}
	return &socFlowEnv{ctx: ctx, st: st, svc: svc, conn: c}
}

func (e *socFlowEnv) begin(t *testing.T, hint string) (*Begun, error) {
	t.Helper()
	e.n++
	txn := &store.AuthTransaction{ID: fmt.Sprintf("txn-%d", e.n), TenantID: "ten", ClientID: "client", ExpiresAt: fixedTime.Add(time.Hour)}
	if err := e.st.AuthTransactions().Create(e.ctx, txn); err != nil {
		t.Fatal(err)
	}
	return e.svc.Begin(e.ctx, BeginInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example", Txn: txn, LoginHint: hint,
		Client: &store.Client{TenantID: "ten", ClientID: "client", IsFirstParty: true}, Connection: e.conn})
}

func (e *socFlowEnv) login(t *testing.T, hint string) (*Completion, error) {
	t.Helper()
	begun, err := e.begin(t, hint)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(begun.URL)
	return e.svc.Complete(e.ctx, CompleteInput{Tenant: &store.Tenant{ID: "ten"}, Origin: "https://login.example",
		Params: CallbackParams{State: u.Query().Get("state"), Code: "code-1"}, CookieValue: begun.CookieValue})
}

func TestSocialFlowLogin(t *testing.T) {
	f := amazonFixture(t)
	e := newSocFlowEnv(t, f, "amazon", nil)
	done, err := e.login(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if done.UserID != "amazon|amzn1.account.THROWAWAY" {
		t.Fatalf("user %s", done.UserID)
	}
	u, err := e.st.Users().Get(e.ctx, "ten", done.UserID)
	if err != nil {
		t.Fatal(err)
	}
	id := u.Identities[0]
	if id.Provider != "amazon" || id.UserID != "amzn1.account.THROWAWAY" || !rules.IsSocial(id.Provider) || id.Connection != "amazon-conn" ||
		u.Email != "shopper@example.com" || u.EmailVerified || u.Name != "Test Shopper" {
		t.Fatalf("stored user %+v identity %+v", u, id)
	}
	tok, err := e.st.Federation().GetTokens(e.ctx, store.FederatedIdentityKey{TenantID: "ten", ConnectionID: e.conn.ID, Subject: "amzn1.account.THROWAWAY"})
	if err != nil || len(tok) == 0 {
		t.Fatalf("tokens %v", err)
	}
	// A second login finds the same user.
	again, err := e.login(t, "")
	if err != nil || again.UserID != done.UserID {
		t.Fatalf("repeat login %v %v", again, err)
	}
	if ButtonLabel(&store.Connection{Name: "configured", Strategy: "amazon"}) != "Amazon" {
		t.Fatal("button label")
	}
}

func TestSocialBeginCapability(t *testing.T) {
	f := amazonFixture(t)
	e := newSocFlowEnv(t, f, "amazon", nil)
	e.svc.Store = predecessorStore{e.st}
	if _, err := e.begin(t, ""); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("begin on a store without social.v1: %v", err)
	}
}
