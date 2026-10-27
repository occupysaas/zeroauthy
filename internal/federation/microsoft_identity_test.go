package federation

import (
	"encoding/json"
	"testing"
)

func TestMicrosoftProfile(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
		email  string
	}{
		{"missing email", map[string]any{"preferred_username": "upn@example.com", "email_verified": true}, ""},
		{"email verified ignored", map[string]any{"email": "changed@example.com", "email_verified": true}, "changed@example.com"},
		{"malformed email ignored", map[string]any{"email": 42, "email_verified": true}, ""},
		{"only allowed attributes", map[string]any{"email": "a@example.com", "name": "Name", "given_name": "Given", "family_name": "Family", "nickname": "drop", "picture": "https://example.com/drop", "app_metadata": map[string]any{"admin": true}, "roles": []string{"admin"}, "groups": []string{"admin"}, "authorization": true, "user_metadata": map[string]any{"admin": true}}, "a@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"sub": "Case-Sensitive-Sub", "oid": testMicrosoftOID, "tid": testMicrosoftTenant}
			for k, v := range tc.claims {
				claims[k] = v
			}
			p, err := microsoftProfile(microsoftTestConfig("organizations"), claims)
			if err != nil {
				t.Fatal(err)
			}
			if p.Subject != testMicrosoftTenant+":"+testMicrosoftOID || (tc.email == "" && p.Email != nil) || (tc.email != "" && (p.Email == nil || *p.Email != tc.email)) {
				t.Fatalf("profile %+v", p)
			}
			if p.EmailVerified == nil || *p.EmailVerified {
				t.Fatalf("conservative verification must explicitly clear previous true: %+v", p)
			}
			if p.UserMetadata != nil || p.Nickname != nil || p.Picture != nil {
				t.Fatalf("unmapped attributes escaped: %+v", p)
			}
			if tc.name == "only allowed attributes" && (p.Name == nil || *p.Name != "Name" || p.GivenName == nil || *p.GivenName != "Given" || p.FamilyName == nil || *p.FamilyName != "Family") {
				t.Fatalf("missing allowed attributes: %+v", p)
			}
		})
	}
	t.Run("personal subject preserved", func(t *testing.T) {
		p, err := microsoftProfile(microsoftTestConfig("consumers"), map[string]any{"sub": "MiXeD-Subject", "oid": testMicrosoftOID})
		if err != nil || p.Subject != "MiXeD-Subject" {
			t.Fatalf("%+v %v", p, err)
		}
	})
}

// Validated claims and retained key metadata are checked again after JWS verification.
func TestMicrosoftClaims(t *testing.T) {
	claims := map[string]any{"ver": "2.0", "tid": testMicrosoftTenant, "iss": testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0", "nbf": json.Number("1793016000")}
	for _, tc := range []struct {
		name, authority, expected, keyIssuer string
		bad                                  bool
	}{
		{"template organization", "organizations", testMicrosoftTemplate, testMicrosoftTemplate, false},
		{"concrete key", "organizations", testMicrosoftTemplate, testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0", false},
		{"DNS pinned directory", "school.example", testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0", testMicrosoftTemplate, false},
		{"DNS changed directory", "school.example", testMicrosoftBase + "/" + testMicrosoftOtherTenant + "/v2.0", testMicrosoftTemplate, true},
		{"single template refused", "school.example", testMicrosoftTemplate, testMicrosoftTemplate, true},
		{"organizations concrete refused", "organizations", testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0", testMicrosoftTemplate, true},
		{"wrong key binding", "organizations", testMicrosoftTemplate, testMicrosoftBase + "/" + testMicrosoftOtherTenant + "/v2.0", true},
		{"missing key binding", "organizations", testMicrosoftTemplate, "", true},
		{"bad template", "organizations", "https://evil.example/{tenantid}/v2.0", testMicrosoftTemplate, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMicrosoftClaims(microsoftTestConfig(tc.authority), tc.expected, tc.keyIssuer, claims, fixedTime)
			if (err != nil) != tc.bad {
				t.Fatalf("error %v want bad %v", err, tc.bad)
			}
		})
	}
}
