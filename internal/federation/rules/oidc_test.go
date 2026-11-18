package rules

import (
	"maps"
	"strings"
	"testing"
)

func enterpriseOptions() map[string]any {
	return map[string]any{"client_id": "client", "scope": "openid profile", "discovery_url": "https://provider.example/.well-known/openid-configuration"}
}
func TestOIDCTypeDefault(t *testing.T) {
	o := enterpriseOptions()
	if cfg, errs := Parse(Input{Strategy: OIDC, Options: o}); len(errs) > 0 || cfg.Channel != "front_channel" {
		t.Fatal(cfg, errs)
	}
}
func TestOIDCEndpointsExplicit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		bad    bool
	}{
		{"front", func(o map[string]any) {}, false},
		{"back missing token", func(o map[string]any) { o["type"] = "back_channel"; o["client_secret"] = "fixture" }, true},
		{"http", func(o map[string]any) { o["issuer"] = "http://provider.example" }, true},
		{"missing jwks", func(o map[string]any) { delete(o, "jwks_uri") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := enterpriseOptions()
			delete(o, "discovery_url")
			o["issuer"] = "https://provider.example"
			o["authorization_endpoint"] = "https://provider.example/authorize"
			o["jwks_uri"] = "https://provider.example/jwks"
			tc.mutate(o)
			_, errs := Parse(Input{Strategy: OIDC, Options: o})
			if (len(errs) > 0) != tc.bad {
				t.Fatalf("errors=%v", errs)
			}
		})
	}
}
func TestOIDCClientSecretByChannel(t *testing.T) {
	for _, tc := range []struct {
		channel, method string
		secret, bad     bool
	}{{"front_channel", "", false, false}, {"front_channel", "", true, true}, {"back_channel", "client_secret_post", false, true}, {"back_channel", "private_key_jwt", false, false}} {
		o := enterpriseOptions()
		o["type"] = tc.channel
		if tc.method != "" {
			o["token_endpoint_auth_method"] = tc.method
		}
		if tc.secret {
			o["client_secret"] = "fixture"
		}
		_, errs := Parse(Input{Strategy: OIDC, Options: o})
		if (len(errs) > 0) != tc.bad {
			t.Errorf("%+v: %v", tc, errs)
		}
	}
}
func TestOIDCPKCEModes(t *testing.T) {
	for _, mode := range []string{"auto", "S256", "s256", "plain", "disabled", "sha512"} {
		o := enterpriseOptions()
		o["connection_settings"] = map[string]any{"pkce": mode}
		_, errs := Parse(Input{Strategy: OIDC, Options: o})
		if (len(errs) > 0) != (mode == "sha512") {
			t.Errorf("%s: %v", mode, errs)
		}
	}
}
func TestOIDCAlgLists(t *testing.T) {
	for _, alg := range []string{"RS256", "PS512", "ES512", "none", "HS256"} {
		o := enterpriseOptions()
		o["id_token_signed_response_algs"] = []any{alg}
		_, errs := Parse(Input{Strategy: OIDC, Options: o})
		if (len(errs) > 0) != (alg == "none" || alg == "HS256") {
			t.Errorf("%s: %v", alg, errs)
		}
	}
}
func TestOIDCDPoP(t *testing.T) {
	for _, value := range []any{nil, "ES256"} {
		o := enterpriseOptions()
		o["dpop_signing_alg"] = value
		_, errs := Parse(Input{Strategy: OIDC, Options: o})
		if (len(errs) > 0) != (value != nil) {
			t.Errorf("%v: %v", value, errs)
		}
	}
}
func TestOIDCPARBackChannelOnly(t *testing.T) {
	o := enterpriseOptions()
	o["enable_pushed_authorization_requests"] = true
	if _, errs := Parse(Input{Strategy: OIDC, Options: o}); len(errs) == 0 {
		t.Fatal("PAR on front channel accepted")
	}
}
func TestOIDCMetadataCap(t *testing.T) {
	o := enterpriseOptions()
	o["oidc_metadata"] = map[string]any{"padding": strings.Repeat("x", 128*1024)}
	if _, errs := Parse(Input{Strategy: OIDC, Options: o}); len(errs) == 0 {
		t.Fatal("oversize metadata accepted")
	}
}
func TestOktaDomain(t *testing.T) {
	for _, domain := range []string{"DEV-1.OKTA.COM", "https://x", "x/y", "x:443"} {
		o := map[string]any{"client_id": "client", "client_secret": "fixture", "domain": domain, "scope": "openid"}
		_, errs := Parse(Input{Strategy: "okta", Options: o})
		if (len(errs) > 0) != (domain != "DEV-1.OKTA.COM") {
			t.Errorf("%s: %v", domain, errs)
		}
	}
}
func TestDomainAliases(t *testing.T) {
	base := enterpriseOptions()
	for _, tc := range []struct {
		n      int
		domain string
		bad    bool
	}{{1000, "EXAMPLE.COM", false}, {1001, "a.example", true}, {1, strings.Repeat("a", 257), true}} {
		o := maps.Clone(base)
		a := make([]any, tc.n)
		for i := range a {
			a[i] = tc.domain
		}
		o["domain_aliases"] = a
		_, errs := Parse(Input{Strategy: OIDC, Options: o})
		if (len(errs) > 0) != tc.bad {
			t.Errorf("n=%d: %v", tc.n, errs)
		}
	}
}

func TestOIDCEncryptionAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		field string
		value any
		bad   bool
	}{
		{"id_token_encrypted_response_alg", "RSA-OAEP-256", false}, {"id_token_encrypted_response_alg", "RSA1_5", true},
		{"id_token_encrypted_response_encs", []any{"A256GCM"}, false}, {"id_token_encrypted_response_encs", []any{"bad"}, true},
	} {
		o := enterpriseOptions()
		o[tc.field] = tc.value
		_, errs := Parse(Input{Strategy: OIDC, Options: o})
		if (len(errs) > 0) != tc.bad {
			t.Errorf("%s: %v", tc.field, errs)
		}
	}
}
func TestOktaRestrictions(t *testing.T) {
	for field, value := range map[string]any{"type": "front_channel", "discovery_url": "https://example.com/discovery", "attribute_map": map[string]any{"mapping_mode": "bind_all"}} {
		o := map[string]any{"domain": "dev-1.okta.com", "client_id": "client", "client_secret": "fixture", "scope": "openid"}
		o[field] = value
		if _, errs := Parse(Input{Strategy: Okta, Options: o}); len(errs) == 0 {
			t.Errorf("accepted %s", field)
		}
	}
}
func TestDomainAliasesNormalization(t *testing.T) {
	o := enterpriseOptions()
	o["domain_aliases"] = []any{"CORP.EXAMPLE", "corp.example"}
	cfg, errs := Parse(Input{Strategy: OIDC, Options: o})
	if len(errs) > 0 || len(cfg.DomainAliases) != 1 || cfg.DomainAliases[0] != "corp.example" {
		t.Fatal(cfg.DomainAliases, errs)
	}
	o = map[string]any{"client_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "client_secret": "fixture", "tenant_domain": "corp.example", "domain_aliases": []any{"CORP.EXAMPLE"}}
	cfg, errs = Parse(Input{Strategy: WAAD, Options: o})
	if len(errs) > 0 || len(cfg.DomainAliases) != 1 {
		t.Fatal(cfg, errs)
	}
	if _, errs := Parse(Input{Strategy: Google, Options: map[string]any{"client_id": "client", "client_secret": "fixture", "domain_aliases": []any{"corp.example"}}}); len(errs) == 0 {
		t.Fatal("Google accepted enterprise aliases")
	}
}
