package federation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const testMicrosoftBase = "https://login.microsoftonline.com"
const testMicrosoftTemplate = "https://login.microsoftonline.com/{tenantid}/v2.0"
const testMicrosoftTenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const testMicrosoftOtherTenant = "11111111-2222-3333-4444-555555555555"
const testMicrosoftConsumer = "9188040d-6c67-4c5b-b112-36a304b66dad"

func microsoftTestConfig(authority string) Config {
	cfg := Config{Strategy: StrategyWAAD, MicrosoftAuthority: authority, MicrosoftMultiTenant: authority == "organizations"}
	if authority == "consumers" {
		cfg.Strategy = StrategyWindowsLive
	}
	return cfg
}

func microsoftTestMetadata(authority, issuer string) map[string]any {
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                testMicrosoftBase + "/" + authority + "/oauth2/v2.0/authorize",
		"token_endpoint":                        testMicrosoftBase + "/" + authority + "/oauth2/v2.0/token",
		"jwks_uri":                              testMicrosoftBase + "/common/discovery/v2.0/keys",
		"userinfo_endpoint":                     "https://graph.microsoft.com/oidc/userinfo",
		"token_endpoint_auth_methods_supported": []any{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []any{"S256"},
		"id_token_signing_alg_values_supported": []any{"RS256"},
	}
}

// The fixture serves canonical Microsoft metadata, changing only transport destinations.
func microsoftDiscoveryFixture(t *testing.T, metadata map[string]any) (*Providers, *httptest.Server, *[]string, *sync.Mutex) {
	t.Helper()
	paths := &[]string{}
	mu := &sync.Mutex{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*paths = append(*paths, r.URL.RequestURI())
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ps := NewProviders(FixturePolicy(roots), func() time.Time { return fixedTime }).WithMicrosoftFixture(MicrosoftOverride{AuthorityBaseURL: srv.URL, JWKSURL: srv.URL + "/keys"})
	return ps, srv, paths, mu
}

func TestMicrosoftDiscovery(t *testing.T) {
	ctx := context.Background()
	cache := CacheKey{TenantID: "local", ConnectionID: "connection", Revision: 1}
	for _, tc := range []struct{ name, authority, issuer string }{
		{"personal concrete", "consumers", testMicrosoftBase + "/" + testMicrosoftConsumer + "/v2.0"},
		{"personal template", "consumers", testMicrosoftTemplate},
		{"directory GUID", testMicrosoftTenant, testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0"},
		{"directory DNS", "example.onmicrosoft.com", testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0"},
		{"organizations template", "organizations", testMicrosoftTemplate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps, srv, paths, mu := microsoftDiscoveryFixture(t, microsoftTestMetadata(tc.authority, tc.issuer))
			cfg := microsoftTestConfig(tc.authority)
			// Raw config endpoints must never choose a network destination.
			cfg.DiscoveryURL = "https://attacker.invalid/discovery"
			meta, err := ps.DiscoverMicrosoft(ctx, cache, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if meta.Issuer != tc.issuer || meta.TokenAuthMethod != "client_secret_post" || meta.UserInfoEndpoint != "" || meta.JWKSURI != srv.URL+"/keys" || meta.AuthorizationEndpoint != srv.URL+"/"+tc.authority+"/oauth2/v2.0/authorize" || meta.TokenEndpoint != srv.URL+"/"+tc.authority+"/oauth2/v2.0/token" {
				t.Fatalf("metadata: %+v", meta)
			}
			if _, err := ps.DiscoverMicrosoft(ctx, cache, cfg); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(*paths) != 1 || (*paths)[0] != "/"+tc.authority+"/v2.0/.well-known/openid-configuration" {
				t.Fatalf("requests %v", *paths)
			}
		})
	}
	t.Run("authority scoped JWKS", func(t *testing.T) {
		raw := microsoftTestMetadata("organizations", testMicrosoftTemplate)
		raw["jwks_uri"] = testMicrosoftBase + "/organizations/discovery/v2.0/keys"
		ps, _, _, _ := microsoftDiscoveryFixture(t, raw)
		if _, err := ps.DiscoverMicrosoft(ctx, cache, microsoftTestConfig("organizations")); err != nil {
			t.Fatal(err)
		}
	})
	bad := map[string]func(map[string]any){
		"concrete organizations issuer": func(m map[string]any) { m["issuer"] = testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0" },
		"arbitrary template":            func(m map[string]any) { m["issuer"] = "https://evil.example/{tenantid}/v2.0" },
		"template path":                 func(m map[string]any) { m["issuer"] = testMicrosoftBase + "/{tenantid}/v1.0" },
		"missing issuer":                func(m map[string]any) { delete(m, "issuer") },
		"missing auth support":          func(m map[string]any) { delete(m, "token_endpoint_auth_methods_supported") },
		"basic only":                    func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []any{"client_secret_basic"} },
		"malformed auth support":        func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = "client_secret_post" },
		"mixed type auth support":       func(m map[string]any) { m["token_endpoint_auth_methods_supported"] = []any{"client_secret_post", 1} },
		"no S256":                       func(m map[string]any) { m["code_challenge_methods_supported"] = []any{"plain"} },
		"malformed S256":                func(m map[string]any) { m["code_challenge_methods_supported"] = 1 },
		"no RS256":                      func(m map[string]any) { m["id_token_signing_alg_values_supported"] = []any{"HS256"} },
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		for name, change := range map[string]func(string) string{
			"query":       func(v string) string { return v + "?tenant=evil" },
			"empty query": func(v string) string { return v + "?" },
			"port":        func(v string) string { return "https://login.microsoftonline.com:8443" + v[len(testMicrosoftBase):] },
			"credentials": func(v string) string { return "https://user@login.microsoftonline.com" + v[len(testMicrosoftBase):] },
			"host":        func(v string) string { return "https://attacker.invalid" + v[len(testMicrosoftBase):] },
			"http":        func(v string) string { return "http" + v[5:] },
			"fragment":    func(v string) string { return v + "#fragment" },
			"path":        func(v string) string { return v + "/extra" },
		} {
			bad[field+" "+name] = func(m map[string]any) { m[field] = change(m[field].(string)) }
		}
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			raw := microsoftTestMetadata("organizations", testMicrosoftTemplate)
			mutate(raw)
			ps, _, _, _ := microsoftDiscoveryFixture(t, raw)
			meta, err := ps.DiscoverMicrosoft(ctx, cache, microsoftTestConfig("organizations"))
			if !errors.Is(err, ErrProviderResponse) || meta != (Metadata{}) {
				t.Fatalf("metadata %+v, error %v", meta, err)
			}
			if ps.discovery.len() != 0 {
				t.Fatal("invalid discovery cached")
			}
		})
	}
	for _, tc := range []struct{ name, authority, issuer, pinned string }{
		{"personal wrong tenant", "consumers", testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0", ""},
		{"directory template", testMicrosoftTenant, testMicrosoftTemplate, ""},
		{"directory consumer", "example.com", testMicrosoftBase + "/" + testMicrosoftConsumer + "/v2.0", ""},
		{"directory wrong GUID", testMicrosoftTenant, testMicrosoftBase + "/" + testMicrosoftOtherTenant + "/v2.0", ""},
		{"changed pinned issuer", "example.com", testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0", testMicrosoftBase + "/" + testMicrosoftOtherTenant + "/v2.0"},
		{"uppercase tenant", "example.com", testMicrosoftBase + "/AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps, _, _, _ := microsoftDiscoveryFixture(t, microsoftTestMetadata(tc.authority, tc.issuer))
			cfg := microsoftTestConfig(tc.authority)
			cfg.Issuer = tc.pinned
			if _, err := ps.DiscoverMicrosoft(ctx, cache, cfg); !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("error %v", err)
			}
		})
	}
	t.Run("invalid authority never fetched", func(t *testing.T) {
		ps, _, paths, mu := microsoftDiscoveryFixture(t, nil)
		for _, authority := range []string{"common", "../organizations", "evil.example/path", "https://evil.example", "organizations?x", "EXAMPLE.COM", testMicrosoftConsumer} {
			cfg := microsoftTestConfig(authority)
			if _, err := ps.DiscoverMicrosoft(ctx, cache, cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("authority %q error %v", authority, err)
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if len(*paths) != 0 {
			t.Fatalf("requests %v", *paths)
		}
	})
}
