package scim

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestParseMapping(t *testing.T) {
	m, err := ParseMapping(DefaultMapping())
	if err != nil {
		t.Fatalf("default mapping: %v", err)
	}
	if len(m) != len(DefaultMapping()) {
		t.Fatal("mapping entries lost")
	}
	for name, bad := range map[string][]store.SCIMMapping{
		"unknown auth0 field": {{Auth0: "logins_count", SCIM: "userName"}},
		"blocked":             {{Auth0: "blocked", SCIM: "active"}},
		"user_id":             {{Auth0: "user_id", SCIM: "userName"}},
		"bad scim path":       {{Auth0: "email", SCIM: "emails["}},
		"id":                  {{Auth0: "email", SCIM: "id"}},
		"meta":                {{Auth0: "email", SCIM: "meta.created"}},
		"password":            {{Auth0: "email", SCIM: "password"}},
		"active":              {{Auth0: "email", SCIM: "active"}},
		"filter without sub":  {{Auth0: "email", SCIM: `emails[type eq "work"]`}},
		"scim twice":          {{Auth0: "email", SCIM: "userName"}, {Auth0: "name", SCIM: "userName"}},
		"auth0 twice":         {{Auth0: "email", SCIM: "userName"}, {Auth0: "email", SCIM: "displayName"}},
		"bad metadata path":   {{Auth0: "app_metadata.", SCIM: "title"}},
	} {
		if _, err := ParseMapping(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMappingRoundTrip(t *testing.T) {
	m, _ := ParseMapping(append(DefaultMapping(), store.SCIMMapping{Auth0: "app_metadata.cost.center", SCIM: EnterpriseUser + ":costCenter"},
		store.SCIMMapping{Auth0: "user_metadata.title", SCIM: "title"}))
	var res map[string]any
	_ = json.Unmarshal([]byte(`{"schemas":["`+CoreUser+`"],"userName":"jdoe","externalId":"e-1","displayName":"J Doe",
		"name":{"givenName":"J","familyName":"Doe"},"emails":[{"type":"home","value":"home@example.test"},{"primary":true,"value":"jdoe@example.test"}],
		"title":"Engineer","`+EnterpriseUser+`":{"department":"R&D","costCenter":"42"},"active":true}`), &res)
	u := &store.User{UserID: "samlp|corp|e-1"}
	if err := m.Apply(res, u); err != nil {
		t.Fatal(err)
	}
	if u.Email != "jdoe@example.test" || u.Name != "J Doe" || u.GivenName != "J" || u.FamilyName != "Doe" || u.Nickname != "jdoe" ||
		u.AppMetadata["department"] != "R&D" || u.AppMetadata["cost"].(map[string]any)["center"] != "42" || u.UserMetadata["title"] != "Engineer" {
		t.Fatalf("applied %+v", u)
	}
	out := m.Render(u)
	raw, _ := json.Marshal(out)
	for _, want := range []string{`"userName":"jdoe"`, `"displayName":"J Doe"`, `"givenName":"J"`, `"primary":true`, `"value":"jdoe@example.test"`,
		`"costCenter":"42"`, `"title":"Engineer"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("render lacks %s: %s", want, raw)
		}
	}
	if out[EnterpriseUser].(map[string]any)["department"] != "R&D" {
		t.Errorf("render lacks the department: %s", raw)
	}
	// Absent attributes clear their fields (PUT replaces).
	var bare map[string]any
	_ = json.Unmarshal([]byte(`{"userName":"jdoe2"}`), &bare)
	if err := m.Apply(bare, u); err != nil {
		t.Fatal(err)
	}
	if u.Email != "" || u.Name != "" || u.Nickname != "jdoe2" || u.AppMetadata["department"] != nil || u.UserMetadata["title"] != nil {
		t.Fatalf("not cleared: %+v", u)
	}
	// Attribute names are case-insensitive; a single unmarked email counts as primary.
	var loose map[string]any
	_ = json.Unmarshal([]byte(`{"USERNAME":"x","Emails":[{"value":"only@example.test"}]}`), &loose)
	if err := m.Apply(loose, u); err != nil || u.Nickname != "x" || u.Email != "only@example.test" {
		t.Fatalf("case-insensitive %+v %v", u, err)
	}
	// Values are validated as profile fields.
	var bad map[string]any
	_ = json.Unmarshal([]byte(`{"displayName":"`+strings.Repeat("a", 400)+`"}`), &bad)
	if err := m.Apply(bad, u); err == nil {
		t.Fatal("oversized name accepted")
	}
	_ = json.Unmarshal([]byte(`{"displayName":42}`), &bad)
	if err := m.Apply(bad, u); err == nil {
		t.Fatal("non-string name accepted")
	}
}
