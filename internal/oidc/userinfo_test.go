package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

var uiNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type uiEnv struct {
	km  *keys.Manager
	srv http.Handler
	st  store.Store
}

// failingUsers is a store whose Users().Get fails with an infrastructure error.
type failingUsers struct{ store.Store }

func (f failingUsers) Users() store.Users { return failingUserStore{f.Store.Users()} }

type failingUserStore struct{ store.Users }

func (failingUserStore) Get(context.Context, string, string) (*store.User, error) {
	return nil, errors.New("database unavailable")
}

func newUserinfoEnv(t *testing.T) *uiEnv {
	t.Helper()
	return newUserinfoEnvWith(t, func(s store.Store) store.Store { return s })
}

func newUserinfoEnvWith(t *testing.T, wrap func(store.Store) store.Store) *uiEnv {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	for _, tn := range []*store.Tenant{
		{ID: "ten_a", Name: "acme", Domains: []string{"acme.example.test"}},
		{ID: "ten_b", Name: "globex", Domains: []string{"globex.example.test"}},
	} {
		_ = st.Tenants().Create(ctx, tn)
	}
	_ = st.Users().Create(ctx, &store.User{
		TenantID: "ten_a", UserID: "auth0|1", Email: "alice@acme.test", EmailVerified: true, Name: "Alice",
		Identities: []store.Identity{{Connection: "DB", Provider: "auth0", UserID: "1"}}, UpdatedAt: uiNow,
	})
	_ = st.Users().Create(ctx, &store.User{
		TenantID: "ten_a", UserID: "auth0|blocked", Email: "bob@acme.test", Blocked: true,
		Identities: []store.Identity{{Connection: "DB", Provider: "auth0", UserID: "blocked"}}, UpdatedAt: uiNow,
	})
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{4}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	_ = km.Ensure(ctx, "ten_a")
	_ = km.Ensure(ctx, "ten_b")
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &Handlers{Keys: km, Store: wrap(st), Log: quiet, Now: func() time.Time { return uiNow }}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /userinfo", h.Userinfo)
	mux.HandleFunc("POST /userinfo", h.Userinfo)
	return &uiEnv{km: km, st: st, srv: contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))}
}

func (e *uiEnv) token(t *testing.T, tenantID string, claims map[string]any) string {
	t.Helper()
	base := map[string]any{
		"iss": "https://acme.example.test/", "sub": "auth0|1",
		"aud": []string{"https://api.test", "https://acme.example.test/userinfo"},
		"iat": uiNow.Unix(), "exp": uiNow.Add(time.Hour).Unix(), "scope": "openid email",
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	raw, err := e.km.Sign(context.Background(), tenantID, base)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *uiEnv) call(method, authz string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://acme.example.test/userinfo", nil)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

func TestUserinfo(t *testing.T) {
	e := newUserinfoEnv(t)
	for _, method := range []string{"GET", "POST"} {
		rec := e.call(method, "Bearer "+e.token(t, "ten_a", nil))
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 200 || body["sub"] != "auth0|1" || body["email"] != "alice@acme.test" || body["email_verified"] != true {
			t.Fatalf("%s = %d %v", method, rec.Code, body)
		}
		if _, ok := body["name"]; ok {
			t.Fatal("profile claim returned without profile scope")
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
	}
	// Scheme is case-insensitive (RFC 7235 §2.1).
	if rec := e.call("GET", "bearer "+e.token(t, "ten_a", nil)); rec.Code != 200 {
		t.Fatalf("lowercase scheme = %d", rec.Code)
	}
}

func TestUserinfoRejects(t *testing.T) {
	e := newUserinfoEnv(t)
	cases := map[string]string{
		"no header":        "",
		"basic scheme":     "Basic Zm9vOmJhcg==",
		"garbage":          "Bearer not-a-token",
		"other tenant key": "Bearer " + e.token(t, "ten_b", nil),
		"expired":          "Bearer " + e.token(t, "ten_a", map[string]any{"exp": uiNow.Add(-time.Second).Unix()}),
		"wrong issuer":     "Bearer " + e.token(t, "ten_a", map[string]any{"iss": "https://globex.example.test/"}),
		"api-only aud":     "Bearer " + e.token(t, "ten_a", map[string]any{"aud": "https://api.test"}),
		"unknown user":     "Bearer " + e.token(t, "ten_a", map[string]any{"sub": "auth0|missing"}),
		"blocked user":     "Bearer " + e.token(t, "ten_a", map[string]any{"sub": "auth0|blocked"}),
		"no exp":           "Bearer " + e.token(t, "ten_a", map[string]any{"exp": nil}),
		"no sub":           "Bearer " + e.token(t, "ten_a", map[string]any{"sub": nil}),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.call("GET", header)
			if rec.Code != 401 || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("got %d %v %s", rec.Code, rec.Header(), rec.Body)
			}
		})
	}
}

func TestUserinfoStoreFailureIs500(t *testing.T) {
	e := newUserinfoEnvWith(t, func(s store.Store) store.Store { return failingUsers{s} })
	rec := e.call("GET", "Bearer "+e.token(t, "ten_a", nil))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 500 || body["error"] != "server_error" {
		t.Fatalf("got %d %v", rec.Code, body)
	}
}

func (e *uiEnv) postForm(authz, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://acme.example.test/userinfo", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

// OIDF oidcc-userinfo-post-body: an access token in a form-encoded POST
// body is accepted (RFC 6750 §2.2, OpenID Connect Core §5.3.1).
func TestUserinfoPostBodyToken(t *testing.T) {
	e := newUserinfoEnv(t)
	tok := e.token(t, "ten_a", nil)
	rec := e.postForm("", "access_token="+tok)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 200 || body["sub"] != "auth0|1" || body["email"] != "alice@acme.test" {
		t.Fatalf("body token = %d %v", rec.Code, body)
	}
	if rec := e.postForm("", "access_token=not-a-token"); rec.Code != 401 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("bad body token = %d %v", rec.Code, rec.Header())
	}
}

// RFC 6750 §2: a client MUST NOT use more than one method to send the token.
func TestUserinfoTwoTokenMethodsIs400(t *testing.T) {
	e := newUserinfoEnv(t)
	tok := e.token(t, "ten_a", nil)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"header and body": e.postForm("Bearer "+tok, "access_token="+tok),
		"two body tokens": e.postForm("", "access_token="+tok+"&access_token="+tok),
	} {
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 400 || body["error"] != "invalid_request" {
			t.Errorf("%s = %d %v", name, rec.Code, body)
		}
	}
}

// An oversized form body is 413 payload_too_large, not a generic 400.
func TestUserinfoOversizedBodyIs413(t *testing.T) {
	e := newUserinfoEnv(t)
	rec := e.postForm("", "access_token="+strings.Repeat("a", maxUserinfoFormBytes+1))
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != 413 || body["error"] != "payload_too_large" {
		t.Fatalf("oversized = %d %v", rec.Code, body)
	}
}
