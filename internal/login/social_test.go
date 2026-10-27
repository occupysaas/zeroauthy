package login

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var regexpState = regexp.MustCompile(`name="state" value="([^"]+)"`)

// fakeIDP is a local OpenID provider: the test plays the user at its
// authorization endpoint by reading the redirect and minting a code.
type fakeIDP struct {
	t         *testing.T
	srv       *httptest.Server
	key       *rsa.PrivateKey
	mu        sync.Mutex
	codes     map[string]idpCode
	exchanges atomic.Int32
	// beforeToken runs inside the token request, before it answers: the
	// network wait of a callback.
	beforeToken func()
}

type idpCode struct {
	sub, nonce, challenge, redirect string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	p := &fakeIDP{t: t, codes: map[string]idpCode{}}
	p.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	return p
}

// base is the provider's URL by name: the test certificate covers
// example.com, which the fixture resolver maps to loopback.
func (p *fakeIDP) base() string {
	u, _ := url.Parse(p.srv.URL)
	return "https://example.com:" + u.Port()
}

func (p *fakeIDP) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	iss := p.base()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "code_challenge_methods_supported": []string{"S256"}})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	case "/token":
		p.exchanges.Add(1)
		_ = r.ParseForm()
		p.mu.Lock()
		c, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.PostForm.Get("redirect_uri") != c.redirect {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		if p.beforeToken != nil {
			p.beforeToken()
		}
		claims, _ := json.Marshal(map[string]any{"iss": iss, "aud": "client", "sub": c.sub, "nonce": c.nonce,
			"iat": fixedNow().Unix(), "exp": fixedNow().Add(time.Hour).Unix(), "email": c.sub + "@idp.example", "email_verified": true})
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		obj, _ := signer.Sign(claims)
		tok, _ := obj.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "upstream-at", "token_type": "Bearer", "id_token": tok, "expires_in": 3600})
	}
}

// authorize plays the user at the provider: it reads the redirect, records
// the request and returns the callback path with a code for sub.
func (p *fakeIDP) authorize(t *testing.T, providerURL, sub string) string {
	t.Helper()
	u, err := url.Parse(providerURL)
	if err != nil || !strings.HasPrefix(providerURL, p.base()+"/authorize") {
		t.Fatalf("not a provider redirect: %q", providerURL)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("client_id") != "client" {
		t.Fatalf("authorize request %v", q)
	}
	code := base64.RawURLEncoding.EncodeToString([]byte(sub + q.Get("state")))[:20]
	p.mu.Lock()
	p.codes[code] = idpCode{sub: sub, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	cb, _ := url.Parse(q.Get("redirect_uri"))
	if (cb.Host != "acme.example.test" && cb.Host != "login.acme.test") || cb.Path != "/login/callback" {
		t.Fatalf("callback %s", cb)
	}
	return cb.Path + "?" + url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
}

// loopbackResolver maps every name to loopback (fixtures only).
type loopbackResolver struct{}

func (loopbackResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

var (
	handoffAction = regexp.MustCompile(`<form method="get" action="([^"]+)">`)
	handoffInput  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
)

// providerURL is where a social start sends the browser: a 303 for an
// explicit selection, an auto-submitted GET page (whose form-action admits
// only the provider) for a posted choice.
func providerURL(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code == 303 {
		return rec.Header().Get("Location")
	}
	body := rec.Body.String()
	m := handoffAction.FindStringSubmatch(body)
	if rec.Code != 200 || m == nil {
		t.Fatalf("social start = %d %s", rec.Code, body)
	}
	action := html.UnescapeString(m[1])
	u, _ := url.Parse(action)
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action "+u.Scheme+"://"+u.Host) {
		t.Fatalf("hand-off CSP %q", csp)
	}
	q := url.Values{}
	for _, in := range handoffInput.FindAllStringSubmatch(body, -1) {
		q.Add(html.UnescapeString(in[1]), html.UnescapeString(in[2]))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

type socialEnv struct {
	*env
	idp, google *fakeIDP
	tenant      *store.Tenant
}

func newSocialEnv(t *testing.T) *socialEnv {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	tn := mustTenant(t, e, "acme")
	s := &socialEnv{env: e, idp: newFakeIDP(t), google: newFakeIDP(t), tenant: tn}
	pool := x509.NewCertPool()
	pool.AddCert(s.idp.srv.Certificate())
	pool.AddCert(s.google.srv.Certificate())
	g := s.google.base()
	policy := federation.FixturePolicy(pool)
	policy.Resolver = loopbackResolver{}
	providers := federation.NewProviders(policy, fixedNow).WithGoogleFixture(federation.GoogleOverride{
		Issuer: g, Endpoints: store.FederationEndpoints{AuthorizationURL: g + "/authorize", TokenURL: g + "/token", JWKSURL: g + "/jwks", TokenAuthMethod: "client_secret_post"}})
	e.h.Federation = &federation.FlowService{Service: federation.Service{Wrapper: w, Now: fixedNow}, Store: e.st, Providers: providers}
	add := func(id string, spec connrules.Spec) {
		c := &store.Connection{TenantID: tn.ID, ID: id, CreatedAt: fixedNow(), Origin: store.OriginAPI}
		connrules.Apply(&spec, c)
		sealed, err := federation.SealCredentials(w, tn.ID, id, federation.Credentials{ClientSecret: "provider-secret"})
		if err != nil {
			t.Fatal(err)
		}
		c.FederationSecretsSealed, c.FederationRevision = sealed, 1
		if err := e.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	hidden := false
	add("con_corp", connrules.Spec{Name: "corp", Strategy: "oidc", EnabledClients: []string{"spa", "social-only"}, DisplayName: "Corp SSO",
		Options: connrules.Options{Extra: map[string]any{"type": "back_channel", "client_id": "client",
			"discovery_url": s.idp.base() + "/.well-known/openid-configuration", "scopes": "openid email"}}})
	add("con_google", connrules.Spec{Name: "google-oauth2", Strategy: "google-oauth2", EnabledClients: []string{"spa", "social-only"},
		Options: connrules.Options{Extra: map[string]any{"client_id": "client"}}})
	add("con_hidden", connrules.Spec{Name: "hidden", Strategy: "oidc", EnabledClients: []string{"spa"}, ShowAsButton: &hidden,
		Options: connrules.Options{Extra: map[string]any{"type": "back_channel", "client_id": "client",
			"discovery_url": s.idp.base() + "/.well-known/openid-configuration", "scopes": "openid"}}})
	spa, _ := e.st.Clients().Get(ctx, tn.ID, "spa")
	only := *spa
	only.ClientID, only.Callbacks = "social-only", []string{"https://only.acme.test/cb"}
	if err := e.st.Clients().Create(ctx, &only); err != nil {
		t.Fatal(err)
	}
	return s
}

// authorizeTo runs /authorize and returns the login page location.
func (s *socialEnv) authorizeTo(t *testing.T, b *browser, client string, extra ...string) string {
	t.Helper()
	cb := map[string]string{"spa": "https://app.acme.test/cb", "social-only": "https://only.acme.test/cb"}[client]
	q := url.Values{"client_id": {client}, "redirect_uri": {cb}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"app-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	if rec.Code != 302 {
		t.Fatalf("authorize = %d %s", rec.Code, rec.Body)
	}
	return rec.Header().Get("Location")
}

// toApp checks a redirect back to the application with a code.
func toApp(t *testing.T, rec *httptest.ResponseRecorder, host string) {
	t.Helper()
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc == nil || loc.Host != host || loc.Query().Get("code") == "" || loc.Query().Get("state") != "app-state" {
		t.Fatalf("expected the application callback, got %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

// explicitLogin runs /authorize?connection=name to the provider and back.
func (s *socialEnv) explicitLogin(t *testing.T, b *browser, p *fakeIDP, conn, sub string) *httptest.ResponseRecorder {
	t.Helper()
	page := s.authorizeTo(t, b, "spa", "connection", conn)
	rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
	if rec.Code != 303 {
		t.Fatalf("explicit connection did not redirect upstream: %d %s", rec.Code, rec.Body)
	}
	return b.do(t, "GET", p.authorize(t, rec.Header().Get("Location"), sub), nil)
}

func TestSocialLoginFlow(t *testing.T) {
	ctx := context.Background()
	t.Run("explicit oidc connection", func(t *testing.T) {
		s := newSocialEnv(t)
		b := s.browser("acme.example.test")
		toApp(t, s.explicitLogin(t, b, s.idp, "corp", "Sub-1"), "app.acme.test")
		if b.cookies[session.CookieName] == nil {
			t.Fatal("no session after social login")
		}
		u, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_corp", "Sub-1")
		if err != nil || u.UserID != "oidc|corp|Sub-1" || u.Email != "Sub-1@idp.example" || u.LoginsCount != 1 {
			t.Fatalf("user %+v %v", u, err)
		}
		// Repeat login finds the same user.
		b2 := s.browser("acme.example.test")
		toApp(t, s.explicitLogin(t, b2, s.idp, "corp", "Sub-1"), "app.acme.test")
		if _, n, _ := s.st.Users().List(ctx, s.tenant.ID, &store.UserQuery{Op: store.QueryTerm, Field: "identities.provider", Kind: store.KindString, Value: "oidc"}, store.UserSort{Field: "user_id"}, store.Page{}); n != 1 {
			t.Fatalf("%d oidc users after repeat login", n)
		}
		c, _ := s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
		if connrules.FromConnection(c).FederationIssuer != s.idp.base() {
			t.Fatal("issuer not pinned at first discovery")
		}
	})
	t.Run("google button on a mixed application", func(t *testing.T) {
		s := newSocialEnv(t)
		b := s.browser("acme.example.test")
		page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, "spa"), "https://acme.example.test"), nil)
		body := page.Body.String()
		if page.Code != 200 || !strings.Contains(body, `name="password"`) || !strings.Contains(body, "Continue with Corp SSO") ||
			!strings.Contains(body, `value="google-oauth2"`) || strings.Contains(body, `value="hidden"`) {
			t.Fatalf("login page %d %s", page.Code, body)
		}
		state := regexpState.FindStringSubmatch(body)[1]
		csrf := csrfField.FindStringSubmatch(body)[1]
		rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {state}, "csrf": {csrf}, "connection": {"google-oauth2"}})
		toApp(t, b.do(t, "GET", s.google.authorize(t, providerURL(t, rec), "G-1"), nil), "app.acme.test")
		if u, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_google", "G-1"); err != nil || u.UserID != "google-oauth2|G-1" {
			t.Fatalf("%v %v", u, err)
		}
		// A forged CSRF token starts nothing.
		if rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {state}, "csrf": {"forged"}, "connection": {"google-oauth2"}}); rec.Code == 303 || rec.Code == 200 {
			t.Fatal("social start without CSRF")
		}
	})
	t.Run("hidden connection by explicit selection", func(t *testing.T) {
		s := newSocialEnv(t)
		toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "hidden", "H-1"), "app.acme.test")
	})
	t.Run("social-only application", func(t *testing.T) {
		s := newSocialEnv(t)
		b := s.browser("acme.example.test")
		page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, "social-only"), "https://acme.example.test"), nil)
		body := page.Body.String()
		if page.Code != 200 || strings.Contains(body, `name="password"`) || !strings.Contains(body, `action="/u/login/social"`) {
			t.Fatalf("social-only page %d %s", page.Code, body)
		}
		state := regexpState.FindStringSubmatch(body)[1]
		rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {state}, "csrf": {csrfField.FindStringSubmatch(body)[1]}, "connection": {"corp"}})
		toApp(t, b.do(t, "GET", s.idp.authorize(t, providerURL(t, rec), "Only-1"), nil), "only.acme.test")
	})
	t.Run("no enabled provider", func(t *testing.T) {
		s := newSocialEnv(t)
		b := s.browser("acme.example.test")
		page := s.authorizeTo(t, b, "spa", "connection", "not-enabled")
		if rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil); rec.Code == 303 {
			t.Fatal("unknown connection went upstream")
		}
	})
	t.Run("prompt none never goes upstream", func(t *testing.T) {
		s := newSocialEnv(t)
		b := s.browser("acme.example.test")
		q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"},
			"state": {"app-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}, "connection": {"corp"}}
		rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc == nil || loc.Host != "app.acme.test" || loc.Query().Get("error") != "login_required" || s.idp.exchanges.Load() != 0 {
			t.Fatalf("prompt=none %d %s", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("provider denial", func(t *testing.T) {
		s := newSocialEnv(t)
		b := s.browser("acme.example.test")
		page := s.authorizeTo(t, b, "spa", "connection", "corp")
		rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
		u, _ := url.Parse(rec.Header().Get("Location"))
		cb := "/login/callback?" + url.Values{"error": {"access_denied"}, "error_description": {"upstream detail"}, "state": {u.Query().Get("state")}}.Encode()
		rec = b.do(t, "GET", cb, nil)
		if rec.Code != 401 || strings.Contains(rec.Body.String(), "upstream detail") || s.idp.exchanges.Load() != 0 {
			t.Fatalf("denial %d %s", rec.Code, rec.Body)
		}
		// The database login of the same transaction still works.
		_, state, csrf := b.begin(t)
		toApp(t, b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}), "app.acme.test")
	})
}

func TestSocialCallbackRace(t *testing.T) {
	ctx := context.Background()
	// start returns the browser and the callback path for sub.
	start := func(t *testing.T, s *socialEnv, sub string) (*browser, string) {
		t.Helper()
		b := s.browser("acme.example.test")
		page := s.authorizeTo(t, b, "spa", "connection", "corp")
		rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
		return b, s.idp.authorize(t, rec.Header().Get("Location"), sub)
	}
	t.Run("replay", func(t *testing.T) {
		s := newSocialEnv(t)
		b, cb := start(t, s, "R")
		saved := map[string]*http.Cookie{}
		for k, v := range b.cookies {
			saved[k] = v
		}
		toApp(t, b.do(t, "GET", cb, nil), "app.acme.test")
		b.cookies = saved
		if rec := b.do(t, "GET", cb, nil); rec.Code == 302 {
			t.Fatal("replayed callback completed")
		}
		if n := s.idp.exchanges.Load(); n != 1 {
			t.Fatalf("%d exchanges", n)
		}
	})
	t.Run("wrong browser and malformed", func(t *testing.T) {
		s := newSocialEnv(t)
		b, cb := start(t, s, "W")
		other := s.browser("acme.example.test")
		u, _ := url.Parse(cb)
		for name, req := range map[string]func() *httptest.ResponseRecorder{
			"no cookie":       func() *httptest.ResponseRecorder { return other.do(t, "GET", cb, nil) },
			"duplicate state": func() *httptest.ResponseRecorder { return b.do(t, "GET", cb+"&state=x", nil) },
			"code and error":  func() *httptest.ResponseRecorder { return b.do(t, "GET", cb+"&error=x", nil) },
			"no state": func() *httptest.ResponseRecorder {
				return b.do(t, "GET", "/login/callback?code="+u.Query().Get("code"), nil)
			},
			"oversized": func() *httptest.ResponseRecorder { return b.do(t, "GET", cb+"&pad="+strings.Repeat("x", 17<<10), nil) },
			"wrong host": func() *httptest.ResponseRecorder {
				// A separate jar: real cookies are host-scoped.
				g := &browser{e: s.env, host: "globex.example.test", cookies: map[string]*http.Cookie{}}
				for k, v := range b.cookies {
					g.cookies[k] = v
				}
				return g.do(t, "GET", cb, nil)
			},
		} {
			if rec := req(); rec.Code == 302 {
				t.Fatalf("%s completed", name)
			}
		}
		if n := s.idp.exchanges.Load(); n != 0 {
			t.Fatalf("%d exchanges for rejected callbacks", n)
		}
		toApp(t, b.do(t, "GET", cb, nil), "app.acme.test")
	})
	t.Run("concurrent callbacks", func(t *testing.T) {
		s := newSocialEnv(t)
		b, cb := start(t, s, "C")
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := &browser{e: s.env, host: b.host, cookies: map[string]*http.Cookie{}}
				for k, v := range b.cookies {
					c.cookies[k] = v
				}
				if rec := c.send("GET", cb, nil); rec.Code == 302 {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || s.idp.exchanges.Load() != 1 {
			t.Fatalf("%d completions, %d exchanges", wins.Load(), s.idp.exchanges.Load())
		}
	})
	for name, during := range map[string]func(s *socialEnv){
		"config change": func(s *socialEnv) {
			c, _ := s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
			c.FederationRevision++
			_ = s.st.Connections().Update(ctx, c)
		},
		"disabled for the application": func(s *socialEnv) {
			c, _ := s.st.Connections().Get(ctx, s.tenant.ID, "con_corp")
			c.EnabledClients = []string{"social-only"}
			_ = s.st.Connections().Update(ctx, c)
		},
		"connection deleted": func(s *socialEnv) { _ = s.st.Connections().Delete(ctx, s.tenant.ID, "con_corp") },
		"user deleted":       func(s *socialEnv) { _ = s.st.Users().Delete(ctx, s.tenant.ID, "oidc|corp|D") },
		"user blocked": func(s *socialEnv) {
			u, _ := s.st.Users().Get(ctx, s.tenant.ID, "oidc|corp|D")
			u.Blocked = true
			_ = s.st.Users().Update(ctx, u)
		},
		"transaction expired": func(s *socialEnv) {
			_, _ = s.st.AuthTransactions().DeleteExpired(ctx, fixedNow().Add(time.Hour))
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSocialEnv(t)
			// An existing user for the deletion and blocking cases.
			toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "corp", "D"), "app.acme.test")
			before, _ := s.st.Sessions().ListByUser(ctx, s.tenant.ID, "oidc|corp|D")
			b, cb := start(t, s, "D")
			s.idp.beforeToken = func() { during(s) }
			rec := b.do(t, "GET", cb, nil)
			if rec.Code == 302 {
				t.Fatalf("completed after %s", name)
			}
			after, _ := s.st.Sessions().ListByUser(ctx, s.tenant.ID, "oidc|corp|D")
			for _, a := range after {
				if !slices.ContainsFunc(before, func(x *store.LoginSession) bool { return x.ID == a.ID }) {
					t.Fatalf("a session was created after %s", name)
				}
			}
			if name == "user deleted" {
				if _, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_corp", "D"); err == nil {
					t.Fatal("an in-flight attempt resurrected the deleted user")
				}
				// A fresh attempt may provision it again.
				s.idp.beforeToken = nil
				toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "corp", "D"), "app.acme.test")
			}
		})
	}
}

func TestSocialProtection(t *testing.T) {
	ctx := context.Background()
	s := newSocialEnv(t)
	tn, _ := s.st.Tenants().Get(ctx, s.tenant.ID)
	tn.ProtectionSettings.SuspiciousIP.Enabled = true
	tn.ProtectionSettings.SuspiciousIP.Shields = []string{"block"}
	tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin.MaxAttempts = 1
	tn.ProtectionSettings.SuspiciousIP.Stage.PreLogin.Rate = 3600000
	tn.ProtectionSettingsInitialized = true
	if err := s.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	b := s.browser("acme.example.test")
	b.remoteAddr = "203.0.113.9:1234"
	page := s.authorizeTo(t, b, "spa", "connection", "corp")
	if rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil); rec.Code != 303 {
		t.Fatalf("first start %d", rec.Code)
	}
	page = s.authorizeTo(t, b, "spa", "connection", "corp")
	if rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("exhausted IP budget: %d %s", rec.Code, rec.Body)
	}
	if s.idp.exchanges.Load() != 0 {
		t.Fatal("provider contacted")
	}
}

// A required challenge is shown before an explicit selection goes upstream,
// and the social POST must pass it.
func TestSocialCaptchaOnExplicitSelection(t *testing.T) {
	ctx := context.Background()
	s := newSocialEnv(t)
	tn, _ := s.st.Tenants().Get(ctx, s.tenant.ID)
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
	tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
	if err := s.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	stub := &captchaStub{}
	s.h.Protection = &protection.Service{Store: s.st, Now: fixedNow, CaptchaVerifier: stub}
	b := s.browser("acme.example.test")
	page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, "spa", "connection", "corp"), "https://acme.example.test"), nil)
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "js.hcaptcha.com") || !strings.Contains(body, `value="corp"`) {
		t.Fatalf("explicit selection bypassed the challenge: %d %s", page.Code, body)
	}
	state, csrf := regexpState.FindStringSubmatch(body)[1], csrfField.FindStringSubmatch(body)[1]
	if rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {state}, "csrf": {csrf}, "connection": {"corp"}}); handoffAction.MatchString(rec.Body.String()) {
		t.Fatal("social start without the challenge")
	}
	rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {state}, "csrf": {csrf}, "connection": {"corp"}, "h-captcha-response": {"good"}})
	if !strings.HasPrefix(providerURL(t, rec), s.idp.base()+"/authorize") {
		t.Fatalf("solved challenge: %d %s", rec.Code, rec.Body)
	}
}

func TestSocialIdentifierFirst(t *testing.T) {
	s := newSocialEnv(t)
	enableIdentifier(t, s.env)
	b := s.browser("acme.example.test")
	page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, "spa"), "https://acme.example.test"), nil)
	body := page.Body.String()
	if page.Code != 200 || strings.Contains(body, `name="password"`) || !strings.Contains(body, `formaction="/u/login/social"`) {
		t.Fatalf("identifier page %d %s", page.Code, body)
	}
	state, csrf := regexpState.FindStringSubmatch(body)[1], csrfField.FindStringSubmatch(body)[1]
	rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {state}, "csrf": {csrf}, "connection": {"corp"}})
	toApp(t, b.do(t, "GET", s.idp.authorize(t, providerURL(t, rec), "IF-1"), nil), "app.acme.test")
}

// A custom domain removed during the provider round trip ends the login
// before anything is committed.
func TestSocialDomainRemovedDuringCallback(t *testing.T) {
	ctx := context.Background()
	s := newSocialEnv(t)
	tn, _ := s.st.Tenants().Get(ctx, s.tenant.ID)
	tn.Domains = []string{"acme.example.test", "login.acme.test"}
	if err := s.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	b := s.browser("login.acme.test")
	page, _ := url.Parse(s.authorizeTo(t, b, "spa", "connection", "corp"))
	rec := b.do(t, "GET", page.RequestURI(), nil)
	cb := s.idp.authorize(t, providerURL(t, rec), "Moved")
	if u, _ := url.Parse(providerURL(t, rec)); !strings.Contains(u.Query().Get("redirect_uri"), "login.acme.test") {
		t.Fatalf("callback not on the transaction's origin: %s", u.Query().Get("redirect_uri"))
	}
	s.idp.beforeToken = func() {
		cur, _ := s.st.Tenants().Get(ctx, s.tenant.ID)
		cur.Domains = []string{"acme.example.test"}
		_ = s.st.Tenants().Update(ctx, cur)
	}
	if rec := b.do(t, "GET", cb, nil); rec.Code == 302 {
		t.Fatal("completed after the domain was removed")
	}
	if _, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_corp", "Moved"); err == nil {
		t.Fatal("identity committed after the domain was removed")
	}
}
