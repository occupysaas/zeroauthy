package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func setup(t *testing.T) (http.Handler, *keys.Manager) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_acme", Name: "acme", CanonicalHost: "acme.example.test", Domains: []string{"acme.example.test"}}); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	km := keys.NewManager(st.SigningKeys(), w)
	if err := km.Ensure(ctx, "ten_acme"); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Keys: km, Store: st}
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

// TestDiscoveryDeviceEndpoint is covered by TestDiscovery (device_authorization_endpoint and the device grant).
func TestDiscoveryDeviceEndpoint(t *testing.T) { TestDiscovery(t) }

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
		"issuer":                        "https://acme.example.test/",
		"authorization_endpoint":        "https://acme.example.test/authorize",
		"token_endpoint":                "https://acme.example.test/oauth/token",
		"revocation_endpoint":           "https://acme.example.test/oauth/revoke",
		"jwks_uri":                      "https://acme.example.test/.well-known/jwks.json",
		"end_session_endpoint":          "https://acme.example.test/oidc/logout",
		"device_authorization_endpoint": "https://acme.example.test/oauth/device/code",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %s", k, doc[k], v)
		}
	}
	wantLists := map[string][]string{
		"id_token_signing_alg_values_supported": {"HS256", "RS256", "PS256"},
		"grant_types_supported":                 {"authorization_code", "client_credentials", "refresh_token", "password", "http://auth0.com/oauth/grant-type/password-realm", "urn:ietf:params:oauth:grant-type:device_code"},
		"response_types_supported":              {"code"},
		"response_modes_supported":              {"query", "fragment", "form_post", "web_message"},
		"code_challenge_methods_supported":      {"S256"},
		"scopes_supported":                      {"openid", "profile", "email", "address", "phone", "offline_access"},
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
	// Signed request objects (JAR) are processed (D-0035 as amended, D-0063).
	if v, ok := doc["request_parameter_supported"]; !ok || v != true {
		t.Errorf("request_parameter_supported = %v (present %v), want true", v, ok)
	}
	// OIDF oidcc-scope-profile: given_name and family_name are emitted for profile.
	for _, c := range []string{"given_name", "family_name"} {
		if !slices.Contains(doc["claims_supported"].([]any), any(c)) {
			t.Errorf("claims_supported lacks %s", c)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

type noClientCredentialsStore struct{ store.Store }

func (noClientCredentialsStore) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

// TestDiscoveryAuthMethods: private_key_jwt with its three signing
// algorithms (Plan 35, D-0063), advertised only when the store has the
// client_credentials.v1 capability (spec §7).
func TestDiscoveryAuthMethods(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_acme", Name: "acme", CanonicalHost: "acme.example.test", Domains: []string{"acme.example.test"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		store   store.Store
		methods []string
		algs    []string
	}{
		{"available", st, []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"}, []string{"RS256", "RS384", "PS256"}},
		{"unavailable", noClientCredentialsStore{st}, []string{"client_secret_basic", "client_secret_post", "none"}, nil},
		{"no store", nil, []string{"client_secret_basic", "client_secret_post", "none"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{}
			if tc.store != nil {
				h.Store = tc.store
			}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
			rec := get(contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)), "https://acme.example.test/.well-known/openid-configuration")
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			var methods, algs []string
			_ = json.Unmarshal(doc["token_endpoint_auth_methods_supported"], &methods)
			if raw, ok := doc["token_endpoint_auth_signing_alg_values_supported"]; ok {
				if tc.algs == nil {
					t.Errorf("token_endpoint_auth_signing_alg_values_supported present: %s", raw)
				}
				_ = json.Unmarshal(raw, &algs)
			}
			if !slices.Equal(methods, tc.methods) {
				t.Errorf("token_endpoint_auth_methods_supported = %v, want %v", methods, tc.methods)
			}
			if !slices.Equal(algs, tc.algs) {
				t.Errorf("token_endpoint_auth_signing_alg_values_supported = %v, want %v", algs, tc.algs)
			}
		})
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
			P   string `json:"p"`
			Q   string `json:"q"`
			DP  string `json:"dp"`
			DQ  string `json:"dq"`
			QI  string `json:"qi"`
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
		if k.D != "" || k.P != "" || k.Q != "" || k.DP != "" || k.DQ != "" || k.QI != "" {
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

func TestDiscoveryAdvertisesPAROnlyWhenEnabled(t *testing.T) {
	h, _ := setup(t)
	var off map[string]any
	if err := json.Unmarshal(get(h, "https://acme.example.test/.well-known/openid-configuration").Body.Bytes(), &off); err != nil {
		t.Fatal(err)
	}
	if _, ok := off["pushed_authorization_request_endpoint"]; ok {
		t.Fatalf("PAR endpoint advertised for a tenant without PAR: %v", off)
	}
	if v, ok := off["request_uri_parameter_supported"]; !ok || v != false {
		t.Fatalf("request_uri_parameter_supported = %v (present %v); want false", v, ok)
	}

	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_par", Name: "par", CanonicalHost: "par.example.test", Domains: []string{"par.example.test"},
		PushedAuthorizationRequestsSupported: true}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", (&Handlers{}).Discovery)
	hp := contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux))
	var on map[string]any
	if err := json.Unmarshal(get(hp, "https://par.example.test/.well-known/openid-configuration").Body.Bytes(), &on); err != nil {
		t.Fatal(err)
	}
	if on["pushed_authorization_request_endpoint"] != "https://par.example.test/oauth/par" {
		t.Fatalf("pushed_authorization_request_endpoint = %v", on["pushed_authorization_request_endpoint"])
	}
}

// TestDiscoveryRequestObject: JAR support and its algorithms, advertised only
// when the store has client_credentials.v1 (spec §4, §7).
func TestDiscoveryRequestObject(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten_acme", Name: "acme", CanonicalHost: "acme.example.test", Domains: []string{"acme.example.test"}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		store     store.Store
		supported bool
		algs      []string
	}{
		{"available", st, true, []string{"RS256", "RS384", "PS256"}},
		{"unavailable", noClientCredentialsStore{st}, false, nil},
		{"no store", nil, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{}
			if tc.store != nil {
				h.Store = tc.store
			}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
			rec := get(contract.Wrap(t, tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)), "https://acme.example.test/.well-known/openid-configuration")
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			var supported bool
			if err := json.Unmarshal(doc["request_parameter_supported"], &supported); err != nil || supported != tc.supported {
				t.Errorf("request_parameter_supported = %s, want %v", doc["request_parameter_supported"], tc.supported)
			}
			var algs []string
			if raw, ok := doc["request_object_signing_alg_values_supported"]; ok {
				if tc.algs == nil {
					t.Errorf("request_object_signing_alg_values_supported present: %s", raw)
				}
				_ = json.Unmarshal(raw, &algs)
			}
			if !slices.Equal(algs, tc.algs) {
				t.Errorf("request_object_signing_alg_values_supported = %v, want %v", algs, tc.algs)
			}
		})
	}
}

func TestDiscoveryClaims(t *testing.T) {
	st := memory.New()
	defer st.Close()
	if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "t", Name: "t", Domains: []string{"tenant.example.test"}}); err != nil {
		t.Fatal(err)
	}
	for _, ignore := range []bool{false, true} {
		h := &Handlers{Store: st}
		h.Compat.IgnoreClaimsParameter = ignore
		handler := tenant.NewResolver(st.Tenants(), "", false).Middleware(http.HandlerFunc(h.Discovery))
		rec := get(handler, "https://tenant.example.test/.well-known/openid-configuration")
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		values, ok := out["acr_values_supported"].([]any)
		if !ok || len(values) != 1 || values[0] != "http://schemas.openid.net/pape/policies/2007/06/multi-factor" {
			t.Fatal("supported ACR missing")
		}
		if ignore {
			if _, ok := out["claims_parameter_supported"]; ok {
				t.Fatal("ignored claims advertised")
			}
		} else if out["claims_parameter_supported"] != true {
			t.Fatal("claims support absent")
		}
		for _, scope := range []string{"address", "phone"} {
			found := false
			for _, v := range out["scopes_supported"].([]any) {
				found = found || v == scope
			}
			if !found {
				t.Errorf("missing scope %s", scope)
			}
		}
		for _, claim := range []string{"acr", "amr", "middle_name", "preferred_username", "website", "gender", "birthdate", "zoneinfo", "locale", "phone_number", "phone_number_verified", "address"} {
			found := false
			for _, v := range out["claims_supported"].([]any) {
				found = found || v == claim
			}
			if !found {
				t.Errorf("missing claim %s", claim)
			}
		}
	}
}

func TestRPLogoutDiscoveryFlag(t *testing.T) {
	st := memory.New()
	defer st.Close()
	tn := &store.Tenant{ID: "t", Name: "t", Domains: []string{"tenant.example.test"}, SettingsExtra: map[string]any{"oidc_logout": map[string]any{"rp_logout_end_session_endpoint_discovery": false}}}
	if err := st.Tenants().Create(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Store: st, Sessions: &session.Manager{Store: st}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", h.Discovery)
	mux.HandleFunc("GET /oidc/logout", h.OidcLogout)
	handler := tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)
	rec := get(handler, "https://tenant.example.test/.well-known/openid-configuration")
	var body map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil {
		t.Fatal("invalid discovery response")
	}
	if _, ok := body["end_session_endpoint"]; ok {
		t.Fatal("disabled endpoint still advertised")
	}
	if rec := get(handler, "https://tenant.example.test/oidc/logout"); rec.Code != 200 {
		t.Fatalf("hidden endpoint status=%d", rec.Code)
	}
}
func TestDiscoveryBackchannel(t *testing.T) {
	handler, _ := setup(t)
	rec := get(handler, "https://acme.example.test/.well-known/openid-configuration")
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["backchannel_logout_supported"] != true || body["backchannel_logout_session_supported"] != true {
		t.Fatal("back-channel logout discovery flags absent")
	}
	if _, ok := body["frontchannel_logout_supported"]; ok {
		t.Fatal("unimplemented front-channel logout advertised")
	}
}

func TestGlobalRevocationDiscovery(t *testing.T) {
	h, _ := setup(t)
	rec := get(h, "https://acme.example.test/.well-known/openid-configuration")
	var doc map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &doc) != nil {
		t.Fatal("invalid discovery")
	}
	if doc["global_token_revocation_endpoint"] != "https://acme.example.test/oauth/global-token-revocation/connection/{connectionName}" {
		t.Fatal("missing connection-specific revocation endpoint")
	}
	methods, _ := doc["global_token_revocation_endpoint_auth_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "global-token-revocation+jwt" {
		t.Fatal("missing revocation authentication method")
	}
}
