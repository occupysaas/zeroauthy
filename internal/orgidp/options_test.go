package orgidp

import (
	"strings"
	"testing"
)

func TestOrgIdPOptions(t *testing.T) {
	cases := []struct {
		name     string
		strategy string
		in       map[string]any
		wantErr  string
		want     map[string]any // members ToConnection must set
	}{
		{"oidc back channel", "oidc", map[string]any{"type": "back_channel", "client_id": "c", "client_secret": "s", "discovery_url": "https://idp.example/.well-known/openid-configuration"}, "", map[string]any{"type": "back_channel", "client_secret": "s", "scope": "openid profile email"}},
		{"oidc missing discovery", "oidc", map[string]any{"type": "front_channel", "client_id": "c"}, "discovery_url", nil},
		{"oidc bad type", "oidc", map[string]any{"type": "sideways", "client_id": "c", "discovery_url": "https://x"}, "type", nil},
		{"oidc unknown member", "oidc", map[string]any{"type": "front_channel", "client_id": "c", "discovery_url": "https://x", "issuer": "https://x"}, "issuer", nil},
		{"okta", "okta", map[string]any{"domain": "acme.okta.com", "client_id": "c", "client_secret": "s"}, "", map[string]any{"domain": "acme.okta.com", "scope": "openid profile email"}},
		{"okta missing secret", "okta", map[string]any{"domain": "acme.okta.com", "client_id": "c"}, "client_secret", nil},
		{"waad", "waad", map[string]any{"tenant_domain": "acme.onmicrosoft.com", "client_id": "c", "client_secret": "s"}, "", map[string]any{"tenant_domain": "acme.onmicrosoft.com"}},
		{"google-apps", "google-apps", map[string]any{"domain": "acme.example", "client_id": "c", "client_secret": "s"}, "", map[string]any{"domain": "acme.example"}},
		{"adfs server", "adfs", map[string]any{"adfs_server": "https://adfs.acme.example"}, "", map[string]any{"adfs_server": "https://adfs.acme.example"}},
		{"adfs both", "adfs", map[string]any{"adfs_server": "https://a", "fedMetadataXml": "<x/>"}, "adfs_server", nil},
		{"adfs none", "adfs", map[string]any{}, "adfs_server", nil},
		{"samlp metadata", "samlp", map[string]any{"metadataUrl": "https://idp/meta", "signSAMLRequest": true, "idpInitiated": map[string]any{"enabled": true}}, "", map[string]any{"metadataUrl": "https://idp/meta", "idpinitiated": map[string]any{"enabled": true}}},
		{"samlp manual", "samlp", map[string]any{"signInEndpoint": "https://idp/sso", "signingCert": "PEM", "signSAMLRequest": false, "signatureAlgorithm": "rsa-sha256"}, "", map[string]any{"signInEndpoint": "https://idp/sso", "signingCert": "PEM"}},
		{"samlp manual missing cert", "samlp", map[string]any{"signInEndpoint": "https://idp/sso", "signSAMLRequest": false}, "signingCert", nil},
		{"samlp wrong type", "samlp", map[string]any{"metadataUrl": "https://idp/meta", "signSAMLRequest": "yes"}, "signSAMLRequest", nil},
		{"samlp bad algorithm", "samlp", map[string]any{"metadataUrl": "https://idp/meta", "signSAMLRequest": true, "digestAlgorithm": "md5"}, "digestAlgorithm", nil},
		{"pingfederate refused", "pingfederate", map[string]any{"pingFederateBaseUrl": "https://p", "signingCert": "PEM", "signatureAlgorithm": "rsa-sha256", "digestAlgorithm": "sha256", "signSAMLRequest": true}, "pingfederate", nil},
		{"unknown strategy", "github", map[string]any{}, "strategy", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ToConnection(c.strategy, c.in)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err %v, want mention of %s", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range c.want {
				if g, ok := got[k]; !ok || !same(g, v) {
					t.Errorf("%s = %v, want %v (all %v)", k, got[k], v, got)
				}
			}
		})
	}
}

func same(a, b any) bool {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		if len(am) != len(bm) {
			return false
		}
		for k := range am {
			if !same(am[k], bm[k]) {
				return false
			}
		}
		return true
	}
	return a == b
}

// TestFromConnectionNoSecrets: responses carry only the OpenAPI's response
// members, never client secrets or private keys.
func TestFromConnectionNoSecrets(t *testing.T) {
	conn := map[string]any{"client_id": "c", "client_secret": "s3cret", "discovery_url": "https://d", "type": "back_channel", "scope": "openid", "domain": "acme.okta.com",
		"tenant_domain": "t", "adfs_server": "https://a", "metadataUrl": "https://m", "signSAMLRequest": true, "signingCert": "PUBLICPEM", "signing_key": map[string]any{"key": "PRIVATE"},
		"idpinitiated": map[string]any{"enabled": true}, "icon_url": "https://i", "domain_aliases": []any{"acme.example"}}
	for _, s := range Strategies {
		out := FromConnection(s, conn)
		for _, k := range []string{"client_secret", "signing_key", "scope", "domain_aliases", "signingCert", "idpinitiated"} {
			if _, ok := out[k]; ok {
				t.Errorf("%s: %s returned", s, k)
			}
		}
	}
	if o := FromConnection("oidc", conn); o["client_id"] != "c" || o["discovery_url"] != "https://d" || o["type"] != "back_channel" || len(o) != 3 {
		t.Errorf("oidc %v", o)
	}
	if o := FromConnection("samlp", conn); o["cert"] != "PUBLICPEM" || o["metadataUrl"] != "https://m" || o["idpInitiated"] == nil {
		t.Errorf("samlp %v", o)
	}
	if o := FromConnection("waad", conn); o["tenant_domain"] != "t" || o["client_id"] != "c" || o["icon_url"] != "https://i" || len(o) != 3 {
		t.Errorf("waad %v", o)
	}
}

// TestForUpdate: an update may omit the secret (the stored one is kept)
// but not other required members.
func TestForUpdate(t *testing.T) {
	if _, err := ForUpdate("okta", map[string]any{"domain": "acme.okta.com", "client_id": "c"}); err != nil {
		t.Fatalf("okta without secret: %v", err)
	}
	if _, err := ForUpdate("okta", map[string]any{"client_id": "c"}); err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("okta without domain: %v", err)
	}
	if _, err := ToConnection("okta", map[string]any{"domain": "acme.okta.com", "client_id": "c"}); err == nil {
		t.Fatal("create without secret accepted")
	}
}
