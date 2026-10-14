// internal/authz/handlers_test.go
package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

type env struct {
	*fixture
	h   *Handlers
	srv http.Handler
}

func newEnv(t *testing.T) *env {
	f := newFixture(t)
	sm := &session.Manager{Store: f.st, Now: fixedNow}
	h := &Handlers{Store: f.st, Sessions: sm, Now: fixedNow}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", h.Authorize)
	return &env{fixture: f, h: h, srv: contract.Wrap(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux))}
}

func (e *env) get(t *testing.T, q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

// login creates a session for alice directly and returns its cookie.
func (e *env) login(t *testing.T, authTime time.Time) *http.Cookie {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, "Username-Password-Authentication", authTime); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

func location(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNoSessionStartsLogin(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, goodQuery())
	loc := location(t, rec)
	if loc.Path != "/u/login" || loc.Query().Get("state") == "" {
		t.Fatalf("Location = %s", loc)
	}
	txnID := loc.Query().Get("state")
	var txnCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == TxnCookiePrefix+txnID {
			txnCookie = c
		}
	}
	if txnCookie == nil || !txnCookie.HttpOnly || !txnCookie.Secure || txnCookie.Path != "/u" || txnCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("txn cookie = %+v", txnCookie)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txnID)
	if err != nil {
		t.Fatal(err)
	}
	if txn.CookieHash != secrets.HashToken(txnCookie.Value) || txn.ClientID != "spa" || txn.CSRFToken == "" ||
		txn.Params["redirect_uri"] != "https://app.acme.test/callback" || !txn.ExpiresAt.Equal(fixedNow().Add(TxnLifetime)) {
		t.Fatalf("txn = %+v", txn)
	}

	signup := location(t, e.get(t, with(goodQuery(), "screen_hint", "signup")))
	if signup.Path != "/u/signup" {
		t.Fatalf("screen_hint=signup went to %s", signup)
	}
}

func TestSessionIssuesCode(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-time.Minute))
	loc := location(t, e.get(t, with(goodQuery(), "nonce", "n1", "audience", "https://api.acme.test"), ck))
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://app.acme.test/callback" {
		t.Fatalf("redirected to %s", loc)
	}
	code, state := loc.Query().Get("code"), loc.Query().Get("state")
	if len(code) < 40 || state != "st" {
		t.Fatalf("code=%q state=%q", code, state)
	}
	ac, err := e.st.AuthCodes().Consume(context.Background(), e.tenant.ID, secrets.HashToken(code), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if ac.ClientID != "spa" || ac.RedirectURI != "https://app.acme.test/callback" || ac.Nonce != "n1" ||
		ac.Audience != "https://api.acme.test" || ac.CodeChallenge != challenge || ac.CodeChallengeMethod != "S256" ||
		strings.Join(ac.Scopes, " ") != "openid profile" || !ac.ExpiresAt.Equal(fixedNow().Add(CodeLifetime)) ||
		!ac.AuthTime.Equal(fixedNow().Add(-time.Minute)) || ac.SessionID == "" {
		t.Fatalf("code = %+v", ac)
	}
}

func TestResponseModes(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())

	frag := location(t, e.get(t, with(goodQuery(), "response_mode", "fragment"), ck))
	fv, _ := url.ParseQuery(frag.Fragment)
	if frag.RawQuery != "" || fv.Get("code") == "" || fv.Get("state") != "st" {
		t.Fatalf("fragment response = %s", frag)
	}

	rec := e.get(t, with(goodQuery(), "response_mode", "form_post"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="https://app.acme.test/callback"`) || !strings.Contains(rec.Body.String(), `name="code"`) {
		t.Fatalf("form_post = %d %s", rec.Code, rec.Body)
	}

	rec = e.get(t, with(goodQuery(), "response_mode", "web_message", "prompt", "none"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "authorization_response") || !strings.Contains(rec.Body.String(), "code") {
		t.Fatalf("web_message = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.acme.test") {
		t.Fatalf("web_message CSP = %q", rec.Header().Get("Content-Security-Policy"))
	}
}

// Review focus 5.
func TestPromptNoneWithoutSession(t *testing.T) {
	e := newEnv(t)
	loc := location(t, e.get(t, with(goodQuery(), "prompt", "none")))
	if loc.Host != "app.acme.test" || loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
	rec := e.get(t, with(goodQuery(), "prompt", "none", "response_mode", "web_message"))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "login_required") || strings.Contains(body, "<form") {
		t.Fatalf("web_message login_required = %d %s", rec.Code, body)
	}
}

func TestForcedReauthentication(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-10*time.Minute))
	for name, q := range map[string]url.Values{
		"prompt=login":     with(goodQuery(), "prompt", "login"),
		"max_age=0":        with(goodQuery(), "max_age", "0"),
		"max_age exceeded": with(goodQuery(), "max_age", "300"),
		"other connection": with(goodQuery(), "client_id", "web", "redirect_uri", "https://web.acme.test/cb", "connection", "Other-DB", "code_challenge", "", "code_challenge_method", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if loc := location(t, e.get(t, q, ck)); loc.Path != "/u/login" {
				t.Fatalf("Location = %s", loc)
			}
		})
	}
	if loc := location(t, e.get(t, with(goodQuery(), "max_age", "3600"), ck)); loc.Query().Get("code") == "" {
		t.Fatalf("recent session with max_age=3600 should get a code: %s", loc)
	}
	if loc := location(t, e.get(t, with(goodQuery(), "max_age", "0", "prompt", "none"), ck)); loc.Query().Get("error") != "login_required" {
		t.Fatalf("max_age=0 with prompt=none: %s", loc)
	}
}

func TestErrorDelivery(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, with(goodQuery(), "redirect_uri", "https://evil.test/cb"))
	if rec.Code != 400 || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "not registered") {
		t.Fatalf("unregistered redirect = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	loc := location(t, e.get(t, with(goodQuery(), "response_type", "token")))
	if loc.Host != "app.acme.test" || loc.Query().Get("error") != "unsupported_response_type" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestResume(t *testing.T) {
	e := newEnv(t)
	loc := location(t, e.get(t, with(goodQuery(), "response_mode", "fragment")))
	txn, _ := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))

	u, _ := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	rec := httptest.NewRecorder()
	sess, _ := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, "Username-Password-Authentication", fixedNow())

	rec = httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://acme.example.test/u/login", nil)
	e.h.Resume(rec, r, tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}, txn, sess)
	back := location(t, rec)
	fv, _ := url.ParseQuery(back.Fragment)
	if back.Host != "app.acme.test" || fv.Get("code") == "" || fv.Get("state") != "st" {
		t.Fatalf("Resume redirect = %s", back)
	}
	s2, _ := e.st.Sessions().GetByTokenHash(context.Background(), e.tenant.ID, sess.TokenHash)
	if len(s2.ClientIDs) != 1 || s2.ClientIDs[0] != "spa" {
		t.Fatalf("session clients = %v", s2.ClientIDs)
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txn.ID); err == nil {
		t.Fatal("transaction not deleted after resume")
	}
}

// A session made through a connection the client does not have enabled must
// not be reused for that client.
func TestSessionConnectionMustBeEnabledForClient(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	q := with(goodQuery(), "client_id", "other-spa", "redirect_uri", "https://other.acme.test/cb")
	if loc := location(t, e.get(t, q, ck)); loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
	loc := location(t, e.get(t, with(q, "prompt", "none"), ck))
	if loc.Host != "other.acme.test" || loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
		t.Fatalf("prompt=none Location = %s", loc)
	}
}
