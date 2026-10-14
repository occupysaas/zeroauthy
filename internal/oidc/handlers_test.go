package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func setup(t *testing.T) (http.Handler, *keys.Manager) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_acme", Name: "acme", Domains: []string{"acme.example.test"}}); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	if err := km.Ensure(ctx, "ten_acme"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Keys: km}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", h.Jwks)
	return contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)), km
}

func get(h http.Handler, url string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	return rec
}

func TestDiscovery(t *testing.T) {
	h, _ := setup(t)
	rec := get(h, "https://acme.example.test/.well-known/openid-configuration")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"issuer":                 "https://acme.example.test/",
		"authorization_endpoint": "https://acme.example.test/authorize",
		"token_endpoint":         "https://acme.example.test/oauth/token",
		"jwks_uri":               "https://acme.example.test/.well-known/jwks.json",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %s", k, doc[k], v)
		}
	}
	wantLists := map[string][]string{
		"grant_types_supported":                 {"authorization_code", "client_credentials", "refresh_token"},
		"response_types_supported":              {"code"},
		"response_modes_supported":              {"query", "fragment", "form_post", "web_message"},
		"code_challenge_methods_supported":      {"S256"},
		"scopes_supported":                      {"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post", "none"},
	}
	for k, want := range wantLists {
		var got []string
		for _, v := range doc[k].([]any) {
			got = append(got, v.(string))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	if doc["userinfo_endpoint"] != "https://acme.example.test/userinfo" {
		t.Errorf("userinfo_endpoint = %v", doc["userinfo_endpoint"])
	}
	if len(doc["claims_supported"].([]any)) == 0 {
		t.Error("claims_supported is empty")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestJWKS(t *testing.T) {
	h, km := setup(t)
	rec := get(h, "https://acme.example.test/.well-known/jwks.json")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Keys []struct {
			Kid string `json:"kid"`
			D   string `json:"d"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	set, _ := km.JWKS(context.Background(), "ten_acme")
	if len(body.Keys) != 2 || body.Keys[0].Kid != set.Keys[0].KeyID {
		t.Fatalf("keys = %+v", body.Keys)
	}
	for _, k := range body.Keys {
		if k.D != "" {
			t.Fatal("private key material published")
		}
	}
}

func TestUnknownTenant(t *testing.T) {
	h, _ := setup(t)
	if rec := get(h, "https://nobody.test/.well-known/jwks.json"); rec.Code != 404 {
		t.Fatalf("status %d", rec.Code)
	}
}
