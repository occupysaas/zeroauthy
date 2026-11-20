package login

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	ghLoginClient = "Iv1.throwaway"
	ghLoginSecret = "throwaway-github-secret"
	ghLoginToken  = "gho_throwaway-login-token"
)

// ghLoginEnv is the shared social environment with a local GitHub (OAuth
// endpoints and REST API) behind an enabled "github" connection.
type ghLoginEnv struct {
	*socialEnv
	srv      *httptest.Server
	mu       sync.Mutex
	noEmail  bool
	redirect []string
	tokens   int
}

func newGitHubEnv(t *testing.T) *ghLoginEnv {
	t.Helper()
	s := newSocialEnv(t)
	g := &ghLoginEnv{socialEnv: s}
	g.srv = httptest.NewTLSServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	u, _ := url.Parse(g.srv.URL)
	base := "https://example.com:" + u.Port()
	sealed, err := federation.SealCredentials(s.h.Federation.Wrapper, s.tenant.ID, "con_github", federation.Credentials{ClientSecret: ghLoginSecret})
	if err != nil {
		t.Fatal(err)
	}
	spec := connrules.Spec{Name: "github", Strategy: "github", EnabledClients: []string{"spa"}, Options: connrules.Options{Extra: map[string]any{"client_id": ghLoginClient}}}
	conn := &store.Connection{TenantID: s.tenant.ID, ID: "con_github", CreatedAt: fixedNow(), Origin: store.OriginAPI}
	connrules.Apply(&spec, conn)
	conn.FederationSecretsSealed, conn.FederationRevision = sealed, 1
	if err := s.st.Connections().Create(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(g.srv.Certificate())
	policy := federation.FixturePolicy(pool)
	policy.Resolver = loopbackResolver{}
	s.h.Federation.Providers = federation.NewProviders(policy, fixedNow).WithGitHubFixture(federation.GitHubOverride{
		APIBase:   base + "/api",
		Endpoints: federation.Endpoints{AuthorizationURL: base + "/login/oauth/authorize", TokenURL: base + "/login/oauth/access_token", TokenAuthMethod: "client_secret_post"}})
	return g
}

func (g *ghLoginEnv) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/login/oauth/access_token":
		_ = r.ParseForm()
		g.mu.Lock()
		g.tokens++
		g.redirect = append(g.redirect, r.PostForm.Get("redirect_uri"))
		g.mu.Unlock()
		if r.PostForm.Get("client_secret") != ghLoginSecret || r.PostForm.Get("code") != "gh-code" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"` + ghLoginToken + `","token_type":"bearer","scope":"user:email"}`))
	case "/api/user":
		_, _ = w.Write([]byte(`{"id":583231,"login":"octocat","name":"The Octocat","avatar_url":"https://avatars.example/u/583231"}`))
	case "/api/user/emails":
		if g.noEmail {
			_, _ = w.Write([]byte(`[{"email":"unverified@example.com","primary":true,"verified":false}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"email":"octo@example.com","primary":true,"verified":true}]`))
	default:
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{}`))
	}
}

// begin starts an explicit github login on host and returns the upstream URL.
func (g *ghLoginEnv) begin(t *testing.T, b *browser) *url.URL {
	t.Helper()
	page, _ := url.Parse(g.authorizeTo(t, b, "spa", "connection", "github"))
	rec := b.do(t, "GET", page.RequestURI(), nil)
	if rec.Code != 303 {
		t.Fatalf("begin = %d %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || u.Path != "/login/oauth/authorize" {
		t.Fatalf("not the GitHub authorize URL: %v", u)
	}
	return u
}

func (g *ghLoginEnv) callback(t *testing.T, b *browser, up *url.URL) *httptest.ResponseRecorder {
	t.Helper()
	return b.do(t, "GET", "/login/callback?"+url.Values{"code": {"gh-code"}, "state": {up.Query().Get("state")}}.Encode(), nil)
}

func TestGitHubLoginFlow(t *testing.T) {
	ctx := context.Background()
	t.Run("button", func(t *testing.T) {
		s := newGitHubEnv(t)
		b := s.browser("acme.example.test")
		page := b.do(t, "GET", strings.TrimPrefix(s.authorizeTo(t, b, "spa"), "https://acme.example.test"), nil)
		body := page.Body.String()
		if page.Code != 200 || !strings.Contains(body, "Continue with GitHub") {
			t.Fatalf("no GitHub button %d %s", page.Code, body)
		}
		rec := b.do(t, "POST", "/u/login/social", url.Values{"state": {regexpState.FindStringSubmatch(body)[1]}, "csrf": {csrfField.FindStringSubmatch(body)[1]}, "connection": {"github"}})
		if !strings.Contains(providerURL(t, rec), "/login/oauth/authorize") {
			t.Fatalf("button did not start GitHub: %s", providerURL(t, rec))
		}
	})
	t.Run("login", func(t *testing.T) {
		s := newGitHubEnv(t)
		b := s.browser("acme.example.test")
		up := s.begin(t, b)
		q := up.Query()
		if q.Get("client_id") != ghLoginClient || q.Get("redirect_uri") != "https://acme.example.test/login/callback" || q.Get("scope") != "user:email" {
			t.Fatalf("authorize query %v", q)
		}
		toApp(t, s.callback(t, b, up), "app.acme.test")
		u, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_github", "583231")
		if err != nil || u.UserID != "github|583231" || u.Email != "octo@example.com" || !u.EmailVerified || b.cookies[session.CookieName] == nil {
			t.Fatalf("user/session: %+v %v", u, err)
		}
	})
	t.Run("second origin", func(t *testing.T) {
		s := newGitHubEnv(t)
		tn, _ := s.st.Tenants().Get(ctx, s.tenant.ID)
		tn.Domains = []string{"acme.example.test", "login.acme.test"}
		if err := s.st.Tenants().Update(ctx, tn); err != nil {
			t.Fatal(err)
		}
		b := s.browser("login.acme.test")
		up := s.begin(t, b)
		if got := up.Query().Get("redirect_uri"); got != "https://login.acme.test/login/callback" {
			t.Fatalf("authorize redirect_uri = %s", got)
		}
		toApp(t, s.callback(t, b, up), "app.acme.test")
		if len(s.redirect) != 1 || s.redirect[0] != "https://login.acme.test/login/callback" {
			t.Fatalf("token redirect_uri = %v", s.redirect)
		}
	})
	t.Run("email required", func(t *testing.T) {
		s := newGitHubEnv(t)
		s.noEmail = true
		b := s.browser("acme.example.test")
		rec := s.callback(t, b, s.begin(t, b))
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "needs a verified primary email address") || b.cookies[session.CookieName] != nil {
			t.Fatalf("email required = %d %s", rec.Code, rec.Body)
		}
		if _, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_github", "583231"); err == nil {
			t.Fatal("user provisioned without a verified email")
		}
	})
	t.Run("blocked user", func(t *testing.T) {
		s := newGitHubEnv(t)
		first := s.browser("acme.example.test")
		toApp(t, s.callback(t, first, s.begin(t, first)), "app.acme.test")
		b := s.browser("acme.example.test")
		u, _ := s.st.Users().Get(ctx, s.tenant.ID, "github|583231")
		u.Blocked = true
		if err := s.st.Users().Update(ctx, u); err != nil {
			t.Fatal(err)
		}
		rec := s.callback(t, b, s.begin(t, b))
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), "This account has been blocked") || b.cookies[session.CookieName] != nil {
			t.Fatalf("blocked = %d %s", rec.Code, rec.Body)
		}
	})
}
