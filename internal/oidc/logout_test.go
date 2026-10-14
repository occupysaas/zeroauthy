package oidc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	tn := &store.Tenant{ID: "ten_a", Name: "acme", Domains: []string{"acme.example.test"}, AllowedLogoutURLs: []string{"https://acme.test/bye"}}
	for _, x := range []*store.Tenant{tn, {ID: "ten_b", Name: "globex", Domains: []string{"globex.example.test"}}} {
		if err := st.Tenants().Create(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*store.Client{
		{TenantID: "ten_a", ClientID: "spa", AllowedLogoutURLs: []string{
			"https://app.acme.test/bye", "https://app.acme.test/bye?from=oidc", "https://*.preview.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "other", AllowedLogoutURLs: []string{"https://other.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "wild-first", AllowedLogoutURLs: []string{"https://*.preview.acme.test/bye", "https://wild.acme.test/bye"}},
		{TenantID: "ten_a", ClientID: "no-urls"},
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
		"client URL":            {url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye"}}, "https://app.acme.test/bye"},
		"query not compared":    {url.Values{"client_id": {"spa"}, "returnTo": {"https://app.acme.test/bye?lang=en"}}, "https://app.acme.test/bye?lang=en"},
		"host case-insensitive": {url.Values{"client_id": {"spa"}, "returnTo": {"https://APP.acme.test/bye"}}, "https://APP.acme.test/bye"},
		"wildcard":              {url.Values{"client_id": {"spa"}, "returnTo": {"https://pr-7.preview.acme.test/bye"}}, "https://pr-7.preview.acme.test/bye"},
		"tenant URL":            {url.Values{"returnTo": {"https://acme.test/bye"}}, "https://acme.test/bye"},
		"first client URL":      {url.Values{"client_id": {"spa"}}, "https://app.acme.test/bye"},
		"first concrete URL":    {url.Values{"client_id": {"wild-first"}}, "https://wild.acme.test/bye"},
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
