package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

func nativeServer(t *testing.T, limited bool) (http.Handler, store.Store) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.Tenants().Create(ctx, &store.Tenant{ID: "native", Name: "native", CanonicalHost: "canonical.example.test", Domains: []string{"canonical.example.test", "login.example.test"}, DefaultDirectory: "Database"}))
	must(st.Clients().Create(ctx, &store.Client{TenantID: "native", ClientID: "app", IsFirstParty: true, AppType: "native", TokenEndpointAuthMethod: store.AuthMethodNone, GrantTypes: []string{clientrules.GrantPasskey}, WebOrigins: []string{"https://app.example.test"}, Mobile: &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "TEAMID", AppBundleIdentifier: "com.example.app"}, Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{strings.Repeat("AB:", 31) + "AB"}}}}))
	must(st.Connections().Create(ctx, &store.Connection{TenantID: "native", ID: "db", Name: "Database", Strategy: store.StrategyDatabase, EnabledClients: []string{"app"}, Extra: map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}}))
	must(st.HostedLogins().Put(ctx, &store.HostedLoginConfig{TenantID: "native", Prompts: map[string]any{"identifier_first": true, "universal_login_experience": "new"}}, 0))
	wrapper, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	deps := Deps{Store: st, Wrapper: wrapper, Resolver: tenant.NewResolver(st.Tenants(), "", false), Sessions: &session.Manager{Store: st}, Passkeys: passkey.NewService(st, rpid.Policy{}, nil)}
	if limited {
		deps.RateLimit = ratelimit.New(ratelimit.Config{Enabled: true, MaxKeys: 1000, Groups: map[ratelimit.Group]ratelimit.Rate{ratelimit.GroupOther: {PerSecond: 0.0001, Burst: 1}}})
	}
	return New(deps), st
}
func TestPasskeyNativeRoutes(t *testing.T) {
	h, _ := nativeServer(t, false)
	h = contract.Wrap(t, h)
	for _, path := range []string{"/passkey/register", "/passkey/challenge"} {
		body := `{"client_id":"app","user_profile":{"email":"native@example.test"}}`
		r := httptest.NewRequest("POST", "https://login.example.test"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("route %s %d %s", path, w.Code, w.Body)
		}
	}
	for _, path := range []string{"/.well-known/apple-app-site-association", "/.well-known/assetlinks.json"} {
		w := get(h, "https://login.example.test"+path)
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "max-age=300" || w.Header().Get("Location") != "" {
			t.Fatalf("association route %s %d %v %s", path, w.Code, w.Header(), w.Body)
		}
		if w := get(h, "https://canonical.example.test"+path); w.Code != 404 {
			t.Fatalf("canonical route %d", w.Code)
		}
	}
	w := get(h, "https://login.example.test/.well-known/openid-configuration")
	var discovery map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &discovery)
	for _, grant := range discovery["grant_types_supported"].([]any) {
		if grant == clientrules.GrantPasskey {
			t.Fatal("native grant advertised")
		}
	}
}
func TestPasskeyNativeCORS(t *testing.T) {
	h, _ := nativeServer(t, false)
	for _, path := range []string{"/passkey/register", "/passkey/challenge"} {
		for _, origin := range []string{"https://app.example.test", "https://evil.test"} {
			r := httptest.NewRequest("OPTIONS", "https://login.example.test"+path, nil)
			r.Header.Set("Origin", origin)
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.Header.Set("Access-Control-Request-Headers", "Content-Type")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if origin == "https://app.example.test" {
				if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != origin {
					t.Fatalf("CORS %d %v", w.Code, w.Header())
				}
			} else if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("foreign CORS %d %v", w.Code, w.Header())
			}
		}
	}
}
func TestPasskeyNativeGeneralLimiter(t *testing.T) {
	h, _ := nativeServer(t, true)
	for i := range 2 {
		r := httptest.NewRequest("POST", "https://login.example.test/passkey/challenge", strings.NewReader(`{"client_id":"app"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if i == 0 && w.Code != 200 {
			t.Fatalf("first %d %s", w.Code, w.Body)
		}
		if i == 1 && (w.Code != 429 || !strings.Contains(w.Body.String(), "too_many_requests")) {
			t.Fatalf("limiter %d %s", w.Code, w.Body)
		}
	}
}
