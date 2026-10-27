package federation

import (
	"strings"
	"testing"
)

const microsoftOptions = `{"client_id":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE","client_secret":"secret"`

func TestMicrosoftConfig(t *testing.T) {
	for _, tc := range []struct {
		name, strategy, extra, authority string
		bad                              bool
	}{
		{"personal", "windowslive", "", "consumers", false},
		{"v2", "windowslive", `,"strategy_version":2`, "consumers", false},
		{"v1", "windowslive", `,"strategy_version":1`, "", true},
		{"typed version", "windowslive", `,"strategy_version":"2"`, "", true},
		{"directory", "waad", `,"tenant_domain":"Contoso.Example"`, "contoso.example", false},
		{"guid", "waad", `,"tenant_domain":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"`, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", false},
		{"defaults", "waad", `,"tenant_domain":"contoso.example","identity_api":"microsoft-identity-platform-v2.0","waad_protocol":"openid-connect","userid_attribute":"oid"`, "contoso.example", false},
		{"organizations", "waad", `,"useCommonEndpoint":true`, "organizations", false},
		{"conflict", "waad", `,"useCommonEndpoint":true,"tenant_domain":"contoso.example"`, "", true},
		{"mode type", "waad", `,"useCommonEndpoint":"true"`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseConfig(configSpec(t, tc.strategy, microsoftOptions+tc.extra+`}`))
			if (err != nil) != tc.bad {
				t.Fatalf("error=%v", err)
			}
			if !tc.bad && (c.MicrosoftAuthority != tc.authority || strings.Join(c.Scopes, " ") != "openid profile email") {
				t.Fatalf("config %+v", c)
			}
		})
	}
	for _, tenant := range []string{"https://example.com", "a/b", "a?b", "a:443", "common", "organizations", "consumers", "a b", "9188040d-6c67-4c5b-b112-36a304b66dad"} {
		t.Run(tenant, func(t *testing.T) {
			if _, err := ParseConfig(configSpec(t, "waad", microsoftOptions+`,"tenant_domain":"`+tenant+`"}`)); err == nil {
				t.Fatal("accepted tenant")
			}
		})
	}
	for _, extra := range []string{`,"client_id":"bad"`, `,"scope":["openid","email"]`, `,"scope":"openid profile email"`, `,"scope":["openid","profile","email","offline_access"]`, `,"email_verified":false`, `,"trust_email_verified":true`, `,"domain_aliases":[]`, `,"ext_groups":true`, `,"upstream_params":{"alias":"prompt"}`, `,"discovery_url":"https://example.com"`} {
		t.Run(extra, func(t *testing.T) {
			if _, err := ParseConfig(configSpec(t, "windowslive", microsoftOptions+extra+`}`)); err == nil {
				t.Fatal("accepted unsupported option")
			}
		})
	}
}
func TestMicrosoftConfigUpdate(t *testing.T) {
	s := configSpec(t, "waad", `{"client_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","tenant_domain":"contoso.example"}`)
	s.FederationSecretsSealed = []byte("sealed")
	c, err := ParseConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	n := c
	n.SecretReference = []byte("rotated")
	if !EffectiveChange(c, n) || ValidateConfigUpdate(c, n) != nil {
		t.Fatal("rotation")
	}
	for _, mutate := range []func(*Config){func(n *Config) { n.ClientID = "other" }, func(n *Config) { n.MicrosoftAuthority = "other.example" }, func(n *Config) { n.MicrosoftMultiTenant = true }} {
		n = c
		mutate(&n)
		if ValidateConfigUpdate(c, n) == nil {
			t.Fatal("binding mutable")
		}
	}
	for _, v := range []any{nil, ""} {
		s.Options.Extra["client_secret"] = v
		if _, err := ParseConfig(s); err == nil {
			t.Fatal("invalid replacement accepted")
		}
	}
}

func TestMicrosoftConfigDomainIsolation(t *testing.T) {
	for _, strategy := range []string{"google-oauth2", "oauth2", "oidc"} {
		for _, key := range []string{"domain", "tenant_domain"} {
			s := configSpec(t, strategy, `{"client_id":"client","client_secret":"secret","`+key+`":"contoso.example"}`)
			if _, err := ParseConfig(s); err == nil {
				t.Fatalf("%s accepted %s", strategy, key)
			}
		}
	}
	for _, strategy := range []string{"windowslive", "waad"} {
		base := microsoftOptions
		if strategy == "waad" {
			base += `,"tenant_domain":"contoso.example"`
		}
		for _, key := range []string{"ext_groups", "ext_profile", "ext_nested_groups", "ext_group_memberships", "api_enable_users", "api_enable_groups", "api_enable_contacts", "basic_profile"} {
			for _, value := range []string{`true`, `null`, `"false"`} {
				if _, err := ParseConfig(configSpec(t, strategy, base+`,"`+key+`":`+value+`}`)); err == nil {
					t.Fatalf("%s accepted %s=%s", strategy, key, value)
				}
			}
			if _, err := ParseConfig(configSpec(t, strategy, base+`,"`+key+`":false}`)); err != nil {
				t.Fatal(err)
			}
		}
		for _, m := range []string{"upstream_params", "authParams", "authParamsMap"} {
			for _, key := range []string{"prompt", "claims", "acr_values", "max_age", "issuer", "tenant_domain", "userid_attribute", "graph_api", "domain_aliases"} {
				if _, err := ParseConfig(configSpec(t, strategy, base+`,"`+m+`":{"nested":{"alias":"`+key+`"}}}`)); err == nil {
					t.Fatalf("accepted alias %s", key)
				}
			}
		}
	}
}
