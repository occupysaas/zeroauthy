package myorgrules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	c, err := Parse(json.RawMessage(`{"allowed_strategies":["oidc","samlp"],"connection_deletion_behavior":"allow_if_empty","invitation_landing_client_id":"app","enforce_permission_ceiling":true,"third_party_client_access":{"default_value":"block","allowed_values":["block","allow"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.EnforcePermissionCeiling || c.EnforceSelfAssignmentRestriction || c.InvitationLandingClientID != "app" || len(c.AllowedStrategies) != 2 {
		t.Fatalf("%+v", c)
	}
	// Defaults are filled in the stored form.
	b, _ := json.Marshal(c)
	for _, want := range []string{`"enforce_self_assignment_restriction":false`, `"connection_deletion_behavior":"allow_if_empty"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %s", b, want)
		}
	}
	for name, raw := range map[string]string{
		"not an object":       `[]`,
		"missing strategies":  `{"connection_deletion_behavior":"allow"}`,
		"missing deletion":    `{"allowed_strategies":[]}`,
		"bad strategy":        `{"allowed_strategies":["auth0"],"connection_deletion_behavior":"allow"}`,
		"bad deletion":        `{"allowed_strategies":[],"connection_deletion_behavior":"never"}`,
		"unknown member":      `{"allowed_strategies":[],"connection_deletion_behavior":"allow","x":1}`,
		"third party default": `{"allowed_strategies":[],"connection_deletion_behavior":"allow","third_party_client_access":{"default_value":"allow","allowed_values":["allow"]}}`,
		"third party empty":   `{"allowed_strategies":[],"connection_deletion_behavior":"allow","third_party_client_access":{"default_value":"block","allowed_values":[]}}`,
		"duplicate strategy":  `{"allowed_strategies":["oidc","oidc"],"connection_deletion_behavior":"allow"}`,
		"wrong type":          `{"allowed_strategies":[],"connection_deletion_behavior":"allow","enforce_permission_ceiling":"yes"}`,
	} {
		if _, err := Parse(json.RawMessage(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestThirdPartyDefault(t *testing.T) {
	c, _ := Parse(json.RawMessage(`{"allowed_strategies":[],"connection_deletion_behavior":"allow"}`))
	if c.ThirdParty().DefaultValue != "block" || len(c.ThirdParty().AllowedValues) != 1 {
		t.Fatalf("%+v", c.ThirdParty())
	}
}
