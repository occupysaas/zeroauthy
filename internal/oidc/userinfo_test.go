package oidc

import (
	"bytes"
	"context"
	"encoding/json"
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
}

func newUserinfoEnv(t *testing.T) *uiEnv {
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
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{4}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	_ = km.Ensure(ctx, "ten_a")
	_ = km.Ensure(ctx, "ten_b")
	h := &Handlers{Keys: km, Store: st, Now: func() time.Time { return uiNow }}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /userinfo", h.Userinfo)
	mux.HandleFunc("POST /userinfo", h.Userinfo)
	return &uiEnv{km: km, srv: contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))}
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
