package oidc

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

var logoutNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

type logoutEnv struct {
	st  store.Store
	km  *keys.Manager
	sm  *session.Manager
	tn  *store.Tenant
	mux *http.ServeMux
	srv http.Handler
}

// newLogoutEnv serves the logout endpoints for tenant acme. wrap lets a
// test substitute failing stores behind the session manager.
func newLogoutEnv(t *testing.T, wrap func(store.Store) store.Store) *logoutEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	tn := &store.Tenant{ID: "ten_a", Name: "acme", Domains: []string{"acme.example.test"}, AllowedLogoutURLs: []string{"https://acme.test/bye"},
		EnabledLocales: []string{"en", "fr"},
		CustomText: store.CustomText{
			"logout":    {"fr": {"logout": {"title": "Se déconnecter ?"}}},
			"zeroauthy": {"fr": {"logged-out": {"title": "Vous êtes déconnecté"}}},
		}}
	for _, x := range []*store.Tenant{tn, {ID: "ten_b", Name: "globex", Domains: []string{"globex.example.test"}}} {
		if err := st.Tenants().Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*store.Client{
		{TenantID: "ten_a", ClientID: "spa", AllowedLogoutURLs: []string{
			"https://app.acme.test/bye", "https://app.acme.test/bye?from=oidc", "https://*.preview.acme.test/bye",
			"https://app.acme.test/bye?b=2&a=1"}},
		{TenantID: "ten_a", ClientID: "other", AllowedLogoutURLs: []string{"https://other.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "wild-first", AllowedLogoutURLs: []string{"https://*.preview.acme.test/bye", "https://wild.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "no-urls"},
		{TenantID: "ten_a", ClientID: "query-first", AllowedLogoutURLs: []string{"https://q.acme.test/bye?from=app"}},
		{TenantID: "ten_a", ClientID: "mixed-case", AllowedLogoutURLs: []string{"https://Upper.acme.test/bye", "https://*.Preview.acme.test/cased"}},
	} {
		if err := st.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	for _, id := range []string{"ten_a", "ten_b"} {
		if err := km.Ensure(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if wrap == nil {
		wrap = func(s store.Store) store.Store { return s }
	}
	clock := func() time.Time { return logoutNow }
	sm := &session.Manager{Store: wrap(st), Now: clock}
	h := &Handlers{Keys: km, Store: st, Sessions: sm, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: clock}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v2/logout", h.Logout)
	mux.HandleFunc("GET /oidc/logout", h.OidcLogout)
	mux.HandleFunc("POST /oidc/logout", h.OidcLogout)
	return &logoutEnv{st: st, km: km, sm: &session.Manager{Store: st, Now: clock}, tn: tn, mux: mux,
		srv: contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))}
}

// login starts a session for auth0|1 and returns its cookie and record.
func (e *logoutEnv) login(t *testing.T) (*http.Cookie, *store.LoginSession) {
	t.Helper()
	rec := httptest.NewRecorder()
	s, err := e.sm.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tn, "auth0|1", "DB", logoutNow)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0], s
}

func (e *logoutEnv) do(t *testing.T, method, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, "https://acme.example.test"+target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

func (e *logoutEnv) alive(t *testing.T, s *store.LoginSession) bool {
	t.Helper()
	_, err := e.st.Sessions().GetByTokenHash(context.Background(), s.TenantID, s.TokenHash)
	return err == nil
}

func clearsSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func v2(q url.Values) string { return "/v2/logout?" + q.Encode() }

func TestV2LogoutRedirects(t *testing.T) {
	cases := map[string]struct {
		q    url.Values
		want string
	}{
		"client URL":                {url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}, "https://app.acme.test/bye"},
		"query not compared":        {url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye?lang=en"}}, "https://app.acme.test/bye?lang=en"},
		"host case-insensitive":     {url.Values{"client_id": {"spa"}, "returnTo": {"https://APP.acme.test/bye"}}, "https://APP.acme.test/bye"},
		"wildcard":                  {url.Values{"client_id": {"spa"}, "returnTo": {"https://pr-7.preview.acme.test/bye"}}, "https://pr-7.preview.acme.test/bye"},
		"tenant URL":                {url.Values{"returnTo": {"https://acme.test/bye"}}, "https://acme.test/bye"},
		"first client URL":          {url.Values{"client_id": {"spa"}}, "https://app.acme.test/bye"},
		"first concrete URL":        {url.Values{"client_id": {"wild-first"}}, "https://wild.acme.test/bye"},
		"first URL has query":       {url.Values{"client_id": {"query-first"}}, "https://q.acme.test/bye?from=app"},
		"registered query":          {url.Values{"client_id": {"query-first"}, "returnTo": {"https://q.acme.test/bye?from=app"}}, "https://q.acme.test/bye?from=app"},
		"registered upper host":     {url.Values{"client_id": {"mixed-case"}, "returnTo": {"https://upper.acme.test/bye"}}, "https://upper.acme.test/bye"},
		"registered upper wildcard": {url.Values{"client_id": {"mixed-case"}, "returnTo": {"https://pr-1.preview.acme.test/cased"}}, "https://pr-1.preview.acme.test/cased"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", v2(tc.q), nil, ck)
			if rec.Code != 302 || rec.Header().Get("Location") != tc.want {
				t.Fatalf("got %d %q; want 302 %q", rec.Code, rec.Header().Get("Location"), tc.want)
			}
			if e.alive(t, s) || !clearsSessionCookie(rec) {
				t.Fatal("session not ended")
			}
		})
	}
}

func TestV2LogoutWithoutReturnTo(t *testing.T) {
	for name, q := range map[string]url.Values{"no client": {}, "client without URLs": {"client_id": {"no-urls"}}} {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", v2(q), nil, ck)
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), "logged out") || e.alive(t, s) || !clearsSessionCookie(rec) {
				t.Fatalf("got %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestV2LogoutRefusesUnlistedReturnTo(t *testing.T) {
	cases := map[string]url.Values{
		"extra path segment":     {"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye/more"}},
		"suffix host":            {"client_id": {"spa"}, "returnTo": {"https://app.acme.test.evil.test/bye"}},
		"embedded in path":       {"client_id": {"spa"}, "returnTo": {"https://evil.test/https://app.acme.test/bye"}},
		"another client's URL":   {"client_id": {"spa"}, "returnTo": {"https://other.acme.test/bye"}},
		"tenant URL with client": {"client_id": {"spa"}, "returnTo": {"https://acme.test/bye"}},
		"client URL, no client":  {"returnTo": {"https://app.acme.test/bye"}},
		"javascript":             {"client_id": {"spa"}, "returnTo": {"javascript:alert(1)"}},
		"userinfo":               {"client_id": {"spa"}, "returnTo": {"https://evil.test@app.acme.test/bye"}},
		"unknown client":         {"client_id": {"nope"}, "returnTo": {"https://app.acme.test/bye"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", v2(q), nil, ck)
			if rec.Code != 400 || rec.Header().Get("Location") != "" {
				t.Fatalf("got %d Location=%q", rec.Code, rec.Header().Get("Location"))
			}
			if !e.alive(t, s) || clearsSessionCookie(rec) {
				t.Fatal("an invalid logout request ended the session")
			}
		})
	}
}

func TestV2LogoutWithoutSession(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, _ := e.login(t)
	q := url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}
	for i, cookies := range [][]*http.Cookie{nil, {ck}, {ck}} { // no cookie, then the same session twice
		rec := e.do(t, "GET", v2(q), nil, cookies...)
		if rec.Code != 302 || !clearsSessionCookie(rec) {
			t.Fatalf("call %d: got %d", i, rec.Code)
		}
	}
}

type failingSessionStore struct{ store.Store }

func (f failingSessionStore) Sessions() store.Sessions { return failingSessions{f.Store.Sessions()} }

type failingSessions struct{ store.Sessions }

func (failingSessions) GetByTokenHash(context.Context, string, string) (*store.LoginSession, error) {
	return nil, errors.New("database unavailable")
}

func TestV2LogoutStoreFailure(t *testing.T) {
	e := newLogoutEnv(t, func(s store.Store) store.Store { return failingSessionStore{s} })
	ck, _ := e.login(t)
	rec := e.do(t, "GET", v2(url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}), nil, ck)
	if rec.Code != 500 || rec.Header().Get("Location") != "" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
}

// idToken signs an ID token for auth0|1 issued to spa, with overrides
// (a nil value deletes the claim).
func (e *logoutEnv) idToken(t *testing.T, tenantID string, over map[string]any) string {
	t.Helper()
	c := map[string]any{"iss": "https://acme.example.test/", "sub": "auth0|1", "aud": "spa",
		"iat": logoutNow.Unix(), "exp": logoutNow.Add(time.Hour).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	raw, err := e.km.Sign(context.Background(), tenantID, c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rp(q url.Values) string { return "/oidc/logout?" + q.Encode() }

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func TestOidcLogoutWithMatchingHint(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			q := url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}, "state": {"xyz"}}
			var rec *httptest.ResponseRecorder
			if method == "GET" {
				rec = e.do(t, "GET", rp(q), nil, ck)
			} else {
				rec = e.do(t, "POST", "/oidc/logout", q, ck)
			}
			if rec.Code != 302 || rec.Header().Get("Location") != "https://app.acme.test/bye?state=xyz" {
				t.Fatalf("got %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			if e.alive(t, s) || !clearsSessionCookie(rec) {
				t.Fatal("session not ended")
			}
		})
	}
}

func TestOidcLogoutAccepted(t *testing.T) {
	cases := map[string]struct {
		q    func(e *logoutEnv, s *store.LoginSession) url.Values
		code int
		loc  string
	}{
		"expired hint": {func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID,
				"iat": logoutNow.Add(-2 * time.Hour).Unix(), "exp": logoutNow.Add(-time.Hour).Unix()})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		}, 302, "https://app.acme.test/bye"},
		"logout_hint with tenant URL": {func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://acme.test/bye"}}
		}, 302, "https://acme.test/bye"},
		"registered query kept": {func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "state": {"s1"},
				"post_logout_redirect_uri": {"https://app.acme.test/bye?from=oidc"}}
		}, 302, "https://app.acme.test/bye?from=oidc&state=s1"},
		"registered query byte-exact": {func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "state": {"s"},
				"post_logout_redirect_uri": {"https://app.acme.test/bye?b=2&a=1"}}
		}, 302, "https://app.acme.test/bye?b=2&a=1&state=s"},
		"no redirect uri": {func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})}}
		}, 200, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", rp(tc.q(e, s)), nil, ck)
			if rec.Code != tc.code || rec.Header().Get("Location") != tc.loc || e.alive(t, s) {
				t.Fatalf("got %d %q alive=%v %s", rec.Code, rec.Header().Get("Location"), e.alive(t, s), rec.Body)
			}
		})
	}
}

func TestOidcLogoutWithoutSessionSkipsConfirmation(t *testing.T) {
	e := newLogoutEnv(t, nil)
	rec := e.do(t, "GET", rp(url.Values{"client_id": {"spa"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}), nil)
	if rec.Code != 302 || rec.Header().Get("Location") != "https://app.acme.test/bye" {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestOidcLogoutConfirmation(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, s := e.login(t)
	params := url.Values{"client_id": {"spa"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}, "state": {"st"}}

	// No hint: ask first.
	rec := e.do(t, "GET", rp(params), nil, ck)
	m := csrfField.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil || !e.alive(t, s) ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "form-action 'self' https://app.acme.test;") {
		t.Fatalf("confirmation = %d alive=%v %s", rec.Code, e.alive(t, s), rec.Body)
	}
	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_logout" {
			csrfCookie = c
		}
	}
	if csrfCookie == nil || !csrfCookie.HttpOnly || !csrfCookie.Secure || csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("confirmation cookie = %+v", csrfCookie)
	}
	confirm := func(token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		f := url.Values{"confirm": {"yes"}, "csrf": {token}}
		for k, v := range params {
			f[k] = v
		}
		return e.do(t, "POST", "/oidc/logout", f, cookies...)
	}
	// A forged confirmation fails and keeps the session.
	if rec := confirm("wrong", ck, csrfCookie); rec.Code != 400 || !e.alive(t, s) {
		t.Fatalf("wrong token = %d", rec.Code)
	}
	if rec := confirm(m[1], ck); rec.Code != 400 || !e.alive(t, s) {
		t.Fatalf("missing cookie = %d", rec.Code)
	}
	// The real confirmation logs out.
	rec = confirm(m[1], ck, csrfCookie)
	if rec.Code != 302 || rec.Header().Get("Location") != "https://app.acme.test/bye?state=st" || e.alive(t, s) {
		t.Fatalf("confirmed = %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

var hiddenField = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// The confirmation page posts ui_locales back, so the logged-out page keeps
// the requested language.
func TestOidcLogoutConfirmationKeepsLanguage(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, s := e.login(t)
	rec := e.do(t, "GET", rp(url.Values{"client_id": {"spa"}, "ui_locales": {"fr"}}), nil, ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<html lang="fr" dir="ltr">`) {
		t.Fatalf("confirmation = %d %s", rec.Code, rec.Body)
	}
	form := url.Values{}
	for _, m := range hiddenField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Add(m[1], html.UnescapeString(m[2]))
	}
	if form.Get("ui_locales") != "fr" {
		t.Fatalf("confirmation form lacks ui_locales: %v", form)
	}
	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_logout" {
			csrfCookie = c
		}
	}
	rec = e.do(t, "POST", "/oidc/logout", form, ck, csrfCookie)
	if rec.Code != 200 || e.alive(t, s) || !strings.Contains(rec.Body.String(), `<html lang="fr" dir="ltr">`) {
		t.Fatalf("logged out = %d alive=%v %s", rec.Code, e.alive(t, s), rec.Body)
	}
}

func TestOidcLogoutHintForAnotherSessionAsksFirst(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, s := e.login(t)
	q := url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": "some-other-session"})},
		"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
	if rec := e.do(t, "GET", rp(q), nil, ck); rec.Code != 200 || csrfField.FindString(rec.Body.String()) == "" || !e.alive(t, s) {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestOidcLogoutRejects(t *testing.T) {
	cases := map[string]func(e *logoutEnv, s *store.LoginSession) url.Values{
		"garbage hint": func(*logoutEnv, *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {"not-a-jwt"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"hint from another tenant": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_b", map[string]any{"iss": "https://globex.example.test/", "sid": s.ID})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"hint with foreign issuer": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"iss": "https://evil.test/", "sid": s.ID})},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"hint for another client": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})}, "client_id": {"other"},
				"post_logout_redirect_uri": {"https://other.acme.test/bye"}}
		},
		"unregistered uri": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://evil.test/bye"}}
		},
		"another client's uri": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://other.acme.test/bye"}}
		},
		"query differs": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://app.acme.test/bye?from=x"}}
		},
		"client uri without client": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"contradicting hints": func(e *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"id_token_hint": {e.idToken(t, "ten_a", map[string]any{"sid": s.ID})}, "logout_hint": {"another-sid"},
				"post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"unknown client": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"nope"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}}
		},
		"javascript uri": func(_ *logoutEnv, s *store.LoginSession) url.Values {
			return url.Values{"client_id": {"spa"}, "logout_hint": {s.ID}, "post_logout_redirect_uri": {"javascript:alert(1)"}}
		},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			e := newLogoutEnv(t, nil)
			ck, s := e.login(t)
			rec := e.do(t, "GET", rp(q(e, s)), nil, ck)
			if rec.Code != 400 || rec.Header().Get("Location") != "" || !e.alive(t, s) || clearsSessionCookie(rec) {
				t.Fatalf("got %d Location=%q alive=%v", rec.Code, rec.Header().Get("Location"), e.alive(t, s))
			}
		})
	}
}

func TestLogoutPagesAreLocalized(t *testing.T) {
	e := newLogoutEnv(t, nil)
	ck, _ := e.login(t)
	// /oidc/logout honours its own ui_locales on the confirmation page.
	rec := e.do(t, "GET", rp(url.Values{"client_id": {"spa"}, "post_logout_redirect_uri": {"https://app.acme.test/bye"}, "ui_locales": {"fr"}}), nil, ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Se déconnecter ?") {
		t.Fatalf("confirmation = %d %s", rec.Code, rec.Body)
	}
	// /v2/logout follows Accept-Language.
	r := httptest.NewRequest("GET", "https://acme.example.test/v2/logout", nil)
	r.Header.Set("Accept-Language", "fr")
	out := httptest.NewRecorder()
	e.srv.ServeHTTP(out, r)
	if out.Code != 200 || !strings.Contains(out.Body.String(), "Vous êtes déconnecté") {
		t.Fatalf("logged-out page = %d %s", out.Code, out.Body)
	}
}
