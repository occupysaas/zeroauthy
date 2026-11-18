package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/provider"
)

type appleEnv struct {
	*socialEnv
	upstream *provider.Provider
}

func newAppleEnv(t *testing.T, name, email, pkce bool) *appleEnv {
	t.Helper()
	s := newSocialEnv(t)
	// The reusable provider validates client-secret times against the real clock.
	s.h.Now, s.h.Authz.Now, s.h.Sessions.Now = time.Now, time.Now, time.Now
	var upstream *provider.Provider
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { upstream.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	base := "https://example.com:" + u.Port()
	var err error
	upstream, err = provider.New(base)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := upstream.RegisterApple(provider.AppleRegistration{ServicesID: "com.example.web", TeamID: "ABCDEFGHIJ", KeyID: "1234567890", PublicKey: &key.PublicKey, PKCES256: pkce}); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	secret := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	sealed, err := federation.SealCredentials(s.h.Federation.Wrapper, s.tenant.ID, "con_apple", federation.Credentials{ClientSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	spec := connrules.Spec{Name: "apple", Strategy: "apple", EnabledClients: []string{"spa"}, Options: connrules.Options{Extra: map[string]any{
		"client_id": "com.example.web", "team_id": "ABCDEFGHIJ", "kid": "1234567890", "name": name, "email": email, "set_user_root_attributes": "on_each_login",
	}}}
	conn := &store.Connection{TenantID: s.tenant.ID, ID: "con_apple", CreatedAt: time.Now(), Origin: store.OriginAPI}
	connrules.Apply(&spec, conn)
	conn.FederationSecretsSealed, conn.FederationRevision = sealed, 1
	if err := s.st.Connections().Create(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	policy := federation.FixturePolicy(pool)
	policy.Resolver = loopbackResolver{}
	s.h.Federation.Now = time.Now
	s.h.Federation.Providers = federation.NewProviders(policy, time.Now).WithAppleFixture(federation.AppleOverride{Issuer: base + "/apple", DiscoveryURL: base + "/apple/.well-known/openid-configuration", Endpoints: federation.Endpoints{AuthorizationURL: base + "/apple/authorize", TokenURL: base + "/apple/token", JWKSURL: base + "/apple/jwks", TokenAuthMethod: "client_secret_post"}})
	return &appleEnv{s, upstream}
}

// callback runs the real fixture's browser consent and returns its callback fields.
func (s *appleEnv) callback(t *testing.T, b *browser, sub string) (string, url.Values) {
	t.Helper()
	page := s.authorizeTo(t, b, "spa", "connection", "apple")
	rec := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
	u, err := url.Parse(providerURL(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.HasPrefix(c.Name, federation.AttemptCookiePrefix) && (!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteNoneMode || c.Path != "/login/callback") {
			t.Fatalf("Apple callback cookie: %+v", c)
		}
	}
	q := u.Query()
	if q.Get("nonce") == "" {
		t.Fatal("missing web nonce")
	}
	a, err := s.st.Federation().GetAttempt(context.Background(), s.tenant.ID, federation.StateHash(q.Get("state")))
	if err != nil || a.Issuer != s.upstream.Base+"/apple" || a.Endpoints.TokenURL != s.upstream.Base+"/apple/token" || a.Endpoints.PKCES256 != (q.Get("code_challenge_method") == "S256") {
		t.Fatalf("attempt snapshot: %+v %v", a, err)
	}
	q.Set("decision", "allow")
	q.Set("subject", sub)
	req := httptest.NewRequest("POST", u.Scheme+"://"+u.Host+u.Path, strings.NewReader(q.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	s.upstream.ServeHTTP(out, req)
	if out.Code == 302 {
		callback, _ := url.Parse(out.Header().Get("Location"))
		return "GET", callback.Query()
	}
	if out.Code != 200 {
		t.Fatalf("consent: %d %s", out.Code, out.Body)
	}
	fields := url.Values{}
	for _, in := range handoffInput.FindAllStringSubmatch(out.Body.String(), -1) {
		fields.Add(html.UnescapeString(in[1]), html.UnescapeString(in[2]))
	}
	return "POST", fields
}

func appleComplete(t *testing.T, b *browser, method string, fields url.Values) *httptest.ResponseRecorder {
	t.Helper()
	if method == "GET" {
		return b.do(t, method, "/login/callback?"+fields.Encode(), nil)
	}
	return b.do(t, method, "/login/callback", fields)
}

func TestAppleFormPostCallback(t *testing.T) {
	for _, pkce := range []bool{false, true} {
		t.Run(map[bool]string{false: "no PKCE", true: "S256"}[pkce], func(t *testing.T) {
			s := newAppleEnv(t, true, true, pkce)
			b := s.browser("acme.example.test")
			method, fields := s.callback(t, b, "relay")
			if method != "POST" {
				t.Fatal("expected form_post")
			}
			toApp(t, appleComplete(t, b, method, fields), "app.acme.test")
			u, err := s.st.Users().FindByIdentity(context.Background(), s.tenant.ID, "con_apple", "relay")
			if err != nil || u.UserID != "apple|relay" || u.Email != "relay@privaterelay.appleid.com" || !u.EmailVerified || b.cookies[session.CookieName] == nil {
				t.Fatalf("user/session: %+v %v", u, err)
			}
			if rec := appleComplete(t, b, method, fields); rec.Code != 400 {
				t.Fatalf("replay = %d", rec.Code)
			}
		})
	}
}

func TestAppleUserFieldOnce(t *testing.T) {
	s := newAppleEnv(t, true, true, false)
	for _, name := range []string{"Alice", "Forged"} {
		b := s.browser("acme.example.test")
		method, fields := s.callback(t, b, "names")
		fields.Set("user", `{"name":{"firstName":"`+name+`","lastName":"Example"},"email":"attacker@example.test"}`)
		toApp(t, appleComplete(t, b, method, fields), "app.acme.test")
		u, err := s.st.Users().FindByIdentity(context.Background(), s.tenant.ID, "con_apple", "names")
		if err != nil || u.GivenName != "Alice" || u.FamilyName != "Example" || u.Name != "Alice Example" || u.Email != "names@apple.e2e.test" {
			t.Fatalf("one-time name: %+v %v", u, err)
		}
	}
	t.Run("attempt without name scope ignores forged user", func(t *testing.T) {
		s := newAppleEnv(t, false, true, false)
		b := s.browser("acme.example.test")
		method, fields := s.callback(t, b, "unnamed")
		fields.Set("user", `{"name":{"firstName":"Forged","lastName":"Name"}}`)
		toApp(t, appleComplete(t, b, method, fields), "app.acme.test")
		u, err := s.st.Users().FindByIdentity(context.Background(), s.tenant.ID, "con_apple", "unnamed")
		if err != nil || u.GivenName != "" || u.FamilyName != "" || strings.Contains(u.Name, "Forged") {
			t.Fatalf("scope gate: %+v %v", u, err)
		}
	})
}

func TestAppleUserFieldLimits(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"absent", ""},
		{"malformed", `{broken`},
		{"over 1 KiB", `{"name":{"firstName":"Oversized","lastName":"Profile"},"padding":"` + strings.Repeat("x", 1024) + `"}`},
		{"over 150 characters", `{"name":{"firstName":"` + strings.Repeat("x", 151) + `"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAppleEnv(t, true, true, false)
			b := s.browser("acme.example.test")
			method, fields := s.callback(t, b, "limits")
			fields.Set("user", tc.raw)
			toApp(t, appleComplete(t, b, method, fields), "app.acme.test")
			u, err := s.st.Users().FindByIdentity(context.Background(), s.tenant.ID, "con_apple", "limits")
			if err != nil || u.GivenName != "" || u.FamilyName != "" {
				t.Fatalf("invalid user applied: %+v %v", u, err)
			}
		})
	}
}

func TestCallbackGetStillWorks(t *testing.T) {
	s := newAppleEnv(t, false, false, false)
	b := s.browser("acme.example.test")
	method, fields := s.callback(t, b, "query")
	if method != "GET" {
		t.Fatal("expected query mode")
	}
	toApp(t, appleComplete(t, b, method, fields), "app.acme.test")
	s2 := newSocialEnv(t)
	b2 := s2.browser("acme.example.test")
	page := s2.authorizeTo(t, b2, "spa", "connection", "corp")
	start := b2.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
	found := false
	for _, c := range start.Result().Cookies() {
		if strings.HasPrefix(c.Name, federation.AttemptCookiePrefix) {
			found = true
			if c.SameSite != http.SameSiteLaxMode || !c.Secure {
				t.Fatalf("OIDC cookie: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("missing OIDC attempt cookie")
	}
	toApp(t, b2.do(t, "GET", s2.idp.authorize(t, providerURL(t, start), "get-regression"), nil), "app.acme.test")
}

func TestApplePendingAttemptRotation(t *testing.T) {
	for _, field := range []string{"kid", "app_secret"} {
		t.Run(field, func(t *testing.T) {
			s := newAppleEnv(t, true, true, false)
			b := s.browser("acme.example.test")
			method, fields := s.callback(t, b, "rotated")
			conn, err := s.st.Connections().Get(context.Background(), s.tenant.ID, "con_apple")
			if err != nil {
				t.Fatal(err)
			}
			spec := connrules.FromConnection(conn)
			if field == "kid" {
				spec.Options.Extra["kid"] = "NEWKEY1234"
			} else {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				spec.Options.Extra["app_secret"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			}
			next := *conn
			connrules.Apply(spec, &next)
			if err := federation.ApplyConnection(s.h.Federation.Wrapper, conn, spec, &next); err != nil {
				t.Fatal(err)
			}
			if next.FederationRevision != 2 {
				t.Fatalf("rotation revision=%d", next.FederationRevision)
			}
			if err := s.st.Connections().Update(context.Background(), &next); err != nil {
				t.Fatal(err)
			}
			rec := appleComplete(t, b, method, fields)
			if rec.Code != 400 || b.cookies[session.CookieName] != nil || s.upstream.Exchanges["apple"] != 0 {
				t.Fatalf("rotation accepted: %d", rec.Code)
			}
		})
	}
}

func TestAppleCallbackRejectsAmbiguity(t *testing.T) {
	for _, mode := range []string{"duplicate", "query-body", "oversize", "wrong-cookie", "wrong-origin", "denied", "malformed-form", "wrong-type"} {
		t.Run(mode, func(t *testing.T) {
			s := newAppleEnv(t, true, true, false)
			b := s.browser("acme.example.test")
			_, fields := s.callback(t, b, "reject")
			path := "/login/callback"
			switch mode {
			case "duplicate":
				fields.Add("code", "other")
			case "query-body":
				path += "?code=other"
			case "oversize":
				fields.Set("extra", strings.Repeat("x", 16<<10))
			case "wrong-cookie":
				for k := range b.cookies {
					if strings.HasPrefix(k, federation.AttemptCookiePrefix) {
						b.cookies[k].Value = "wrong"
					}
				}
			case "wrong-origin":
				tn, _ := s.st.Tenants().Get(context.Background(), s.tenant.ID)
				tn.Domains = append(tn.Domains, "login.acme.test")
				if err := s.st.Tenants().Update(context.Background(), tn); err != nil {
					t.Fatal(err)
				}
				b.host = "login.acme.test"
			case "denied":
				fields.Del("code")
				fields.Set("error", "access_denied")
			}
			var rec *httptest.ResponseRecorder
			if mode == "malformed-form" || mode == "wrong-type" {
				raw := fields.Encode()
				contentType := "application/x-www-form-urlencoded"
				if mode == "malformed-form" {
					raw += "&bad=%zz"
				}
				if mode == "wrong-type" {
					contentType = "application/json"
				}
				r := httptest.NewRequest("POST", "https://acme.example.test"+path, strings.NewReader(raw))
				r.Header.Set("Content-Type", contentType)
				for _, c := range b.cookies {
					r.AddCookie(c)
				}
				rec = httptest.NewRecorder()
				s.env.srv.ServeHTTP(rec, r)
			} else {
				rec = b.do(t, "POST", path, fields)
			}
			want := 400
			if mode == "denied" {
				want = 401
			}
			if rec.Code != want || b.cookies[session.CookieName] != nil || s.upstream.Exchanges["apple"] != 0 {
				t.Fatalf("%s: status=%d body=%s", mode, rec.Code, rec.Body)
			}
		})
	}
}

// A malformed request must register every parsed credential before the error
// event or operator logger has a chance to interpolate its value.
func TestAppleCallbackCredentialsScrubbedBeforeErrors(t *testing.T) {
	for _, tc := range []struct{ name, body, query, contentType string }{
		{"missing-state", "code=body-secret", "", "application/x-www-form-urlencoded"},
		{"malformed", "code=body-secret&bad=%zz", "", "application/x-www-form-urlencoded"},
		{"duplicate", "code=body-secret&code=other-secret", "", "application/x-www-form-urlencoded"},
		{"query-body", "code=body-secret", "code=query-secret", "application/x-www-form-urlencoded"},
		{"oversized", "code=body-secret&pad=" + strings.Repeat("x", 16<<10), "", "application/x-www-form-urlencoded"},
		{"wrong-type", "code=body-secret", "", "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			r := httptest.NewRequest("POST", "https://acme.example.test/login/callback?"+tc.query, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			rec := httptest.NewRecorder()
			e.h.SocialCallback(rec, r)
			if rec.Code != 400 {
				t.Fatalf("status=%d", rec.Code)
			}
			for _, secret := range []string{"body-secret", "other-secret", "query-secret"} {
				if strings.Contains(tc.body, secret) || strings.Contains(tc.query, secret) {
					if got := logscrub.MaskText(r.Context(), secret); got != logscrub.Marker {
						t.Fatalf("credential not registered on %s: %s", tc.name, secret)
					}
				}
			}
		})
	}
}
