package api

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// These gates exercise the published schemas: dropping a constraint would
// admit a malformed signing credential, switch or native profile.
func TestAppleConnectionContract(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	ref := doc.Components.Schemas["ConnectionOptionsApple"]
	if ref == nil {
		t.Fatal("missing Apple options schema")
	}
	if secret := ref.Value.Properties["app_secret"]; secret == nil || !secret.Value.WriteOnly {
		t.Fatal("Apple signing key must be write-only")
	}
	for _, tc := range []struct {
		name  string
		body  map[string]any
		valid bool
	}{
		{"patch preserves omitted key", map[string]any{"kid": "KEY1234567"}, true},
		{"empty key", map[string]any{"app_secret": ""}, false},
		{"null key", map[string]any{"app_secret": nil}, false},
		{"short team", map[string]any{"team_id": "TEAM"}, false},
		{"lowercase key id", map[string]any{"kid": "key1234567"}, false},
		{"Services ID", map[string]any{"client_id": "com.example.signin"}, true},
		{"empty Services ID", map[string]any{"client_id": ""}, false},
		{"long Services ID", map[string]any{"client_id": strings.Repeat("x", 256)}, false},
		{"Apple scopes", map[string]any{"scope": "name email", "freeform_scopes": []any{"email"}}, true},
		{"foreign scope", map[string]any{"scope": "openid"}, false},
		{"foreign freeform scope", map[string]any{"freeform_scopes": []any{"profile"}}, false},
		{"scope wire type", map[string]any{"scope": []any{"name"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ref.Value.VisitJSON(tc.body); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
	strategy := doc.Components.Schemas["ConnectionCreate"].Value.AllOf[1].Value.Properties["strategy"].Value
	if err := strategy.VisitJSON("apple"); err != nil {
		t.Fatalf("Apple strategy rejected: %v", err)
	}
}

func TestAppleNativeClientContract(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []string{"ClientSettings", "Client"} {
		ref := doc.Components.Schemas[schema].Value.Properties["native_social_login"]
		if ref == nil {
			t.Fatalf("%s missing native switches", schema)
		}
		for _, provider := range []string{"apple", "facebook", "google"} {
			for _, tc := range []struct {
				value any
				valid bool
			}{
				{map[string]any{"enabled": true}, true},
				{map[string]any{"enabled": false}, true},
				{map[string]any{"enabled": "true"}, false},
				{map[string]any{"enabled": true, "typo": false}, false},
			} {
				if err := ref.Value.VisitJSON(map[string]any{provider: tc.value}); (err == nil) != tc.valid {
					t.Errorf("%s/%s valid=%v, error=%v", schema, provider, tc.valid, err)
				}
			}
		}
		mobile := doc.Components.Schemas[schema].Value.Properties["mobile"].Value
		if err := mobile.VisitJSON(map[string]any{"ios": map[string]any{"team_id": "TEAM123456", "app_bundle_identifier": "com.example.app"}}); err != nil {
			t.Errorf("%s iOS identity: %v", schema, err)
		}
	}
}

func TestAppleNativeProfileContract(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	request := doc.Components.Schemas["TokenRequest"].Value
	if request.Properties["user_profile"] == nil {
		t.Fatal("missing native user_profile")
	}
	for _, tc := range []struct {
		name    string
		profile any
		valid   bool
	}{
		{"name", map[string]any{"name": map[string]any{"firstName": "Jane", "lastName": "Smith"}}, true},
		{"name absent", map[string]any{}, true},
		{"wrong name type", map[string]any{"name": "Jane"}, false},
		{"long name", map[string]any{"name": map[string]any{"firstName": strings.Repeat("a", 151)}}, false},
		{"untrusted email", map[string]any{"email": "other@example.test"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token_type": "http://auth0.com/oauth/token-type/apple-authz-code", "subject_token": "code", "client_id": "native", "user_profile": tc.profile}
			if err := request.VisitJSON(body); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
