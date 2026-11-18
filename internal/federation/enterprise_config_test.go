package federation

import (
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestOIDCEffectiveChangeBumpsRevision(t *testing.T) {
	base := func() connrules.Spec {
		return configSpec(t, "oidc", `{"client_id":"client","scope":"openid","discovery_url":"https://provider.example/discovery"}`)
	}
	before, err := ParseConfig(base())
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]any{"type": "back_channel", "send_back_channel_nonce": false, "connection_settings": map[string]any{"pkce": "plain"}, "id_token_signed_response_algs": []any{"PS256"}, "attribute_map": map[string]any{"mapping_mode": "use_map", "attributes": map[string]any{"name": "Jane"}}, "oidc_metadata": map[string]any{"issuer": "https://provider.example", "authorization_endpoint": "https://provider.example/auth", "jwks_uri": "https://provider.example/keys"}} {
		s := base()
		s.Options.Extra[field] = value
		if field == "type" {
			s.Options.Extra["client_secret"] = "fixture"
		}
		after, err := ParseConfig(s)
		if err != nil {
			t.Fatal(err)
		}
		if !EffectiveChange(before, after) {
			t.Errorf("%s did not invalidate attempts", field)
		}
	}
	s := base()
	s.Options.Extra["icon_url"] = "https://example.com/icon"
	after, err := ParseConfig(s)
	if err != nil || EffectiveChange(before, after) {
		t.Fatal("icon changed effective configuration", err)
	}
}
func TestOIDCImmutable(t *testing.T) {
	for _, strategy := range []string{"oidc", "okta"} {
		options := `{"client_id":"client","scope":"openid","discovery_url":"https://provider.example/discovery","issuer":"https://provider.example"}`
		if strategy == "okta" {
			options = `{"client_id":"client","scope":"openid","client_secret":"fixture","domain":"dev-1.okta.com"}`
		}
		s := configSpec(t, strategy, options)
		before, err := ParseConfig(s)
		if err != nil {
			t.Fatal(err)
		}
		field := "issuer"
		value := "https://different.example"
		if strategy == "okta" {
			field = "domain"
			value = "other.okta.com"
		}
		s.Options.Extra[field] = value
		after, err := ParseConfig(s)
		if err != nil {
			t.Fatal(err)
		}
		if ValidateConfigUpdate(before, after) == nil {
			t.Errorf("changed %s accepted", field)
		}
	}
}

func TestEnterpriseSecretlessWrite(t *testing.T) {
	for _, options := range []string{`{"client_id":"client","scope":"openid","discovery_url":"https://provider.example/discovery"}`, `{"type":"back_channel","client_id":"client","scope":"openid","discovery_url":"https://provider.example/discovery","token_endpoint_auth_method":"private_key_jwt"}`} {
		s := configSpec(t, "oidc", options)
		next := &store.Connection{TenantID: "t", ID: "c", Name: s.Name, Strategy: s.Strategy, Extra: map[string]any{}}
		if err := ApplyConnection(nil, nil, &s, next); err != nil {
			t.Fatal(err)
		}
	}
}
