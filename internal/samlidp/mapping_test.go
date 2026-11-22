package samlidp

import (
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testUser() *store.User {
	return &store.User{TenantID: "t", UserID: "auth0|alice", Email: "alice@example.test", EmailVerified: true, Name: "Alice Doe",
		GivenName: "Alice", FamilyName: "Doe", Nickname: "ally", CreatedAt: time.Unix(1700000000, 0).UTC(),
		AppMetadata: map[string]any{"department": "R&D", "roles": []any{"admin", "dev"}}, UserMetadata: map[string]any{"private": "secret"},
		Identities: []store.Identity{{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: "alice"}}}
}

func attrs(as []samlcore.Attribute) map[string][]string {
	out := map[string][]string{}
	for _, a := range as {
		out[a.Name] = a.Values
	}
	return out
}

func TestMappingDefaults(t *testing.T) {
	m := buildAttributes(testUser(), &store.SAMLAddon{}, map[string]any{"groups": []any{"g1", "g2"}})
	got := attrs(m.Attributes)
	for name, want := range map[string]string{
		samlcore.ClaimNameIdentifier: "auth0|alice", samlcore.ClaimEmail: "alice@example.test", samlcore.ClaimName: "Alice Doe",
		samlcore.ClaimGivenName: "Alice", samlcore.ClaimSurname: "Doe", samlcore.ClaimUPN: "alice@example.test",
		"http://schemas.auth0.com/nickname": "ally", "http://schemas.auth0.com/email_verified": "true",
		"http://schemas.auth0.com/identities/default/provider": "auth0", "http://schemas.auth0.com/identities/default/connection": "Username-Password-Authentication",
		"http://schemas.auth0.com/identities/default/user_id": "alice", "http://schemas.auth0.com/identities/default/isSocial": "false",
	} {
		if len(got[name]) != 1 || got[name][0] != want {
			t.Errorf("%s = %v, want %q", name, got[name], want)
		}
	}
	if strings.Join(got[samlcore.ClaimGroups], ",") != "g1,g2" {
		t.Errorf("groups = %v", got[samlcore.ClaimGroups])
	}
	for name := range got {
		if strings.Contains(name, "metadata") {
			t.Errorf("metadata sent without a mapping: %s", name)
		}
	}
	if m.NameID != "auth0|alice" {
		t.Errorf("NameID %q", m.NameID)
	}
}

func TestMappingOptions(t *testing.T) {
	no, yes := false, true
	addon := &store.SAMLAddon{
		Mappings:       map[string][]string{"email": {"mail", "urn:oid:0.9.2342.19200300.100.1.3"}, "app_metadata.department": {"department"}, "app_metadata.roles": {"roles"}},
		CreateUpnClaim: &no, MapIdentities: &no, MapUnknownClaimsAsIs: &yes,
		NameIdentifierProbes: []string{"mail"},
	}
	got := attrs(buildAttributes(testUser(), addon, nil).Attributes)
	if got["mail"][0] != "alice@example.test" || got["urn:oid:0.9.2342.19200300.100.1.3"][0] != "alice@example.test" || got[samlcore.ClaimEmail] != nil {
		t.Errorf("email mapping replaces the default name: %v", got)
	}
	if got["department"][0] != "R&D" || strings.Join(got["roles"], ",") != "admin,dev" {
		t.Errorf("explicit metadata mappings: %v %v", got["department"], got["roles"])
	}
	if got[samlcore.ClaimUPN] != nil || got["http://schemas.auth0.com/identities/default/provider"] != nil {
		t.Error("UPN or identities sent while disabled")
	}
	if got["nickname"][0] != "ally" || got["http://schemas.auth0.com/nickname"] != nil {
		t.Errorf("mapUnknownClaimsAsIs: %v", got["nickname"])
	}
	if got["user_metadata.private"] != nil || got["private"] != nil {
		t.Error("unmapped metadata leaked")
	}
	if m := buildAttributes(testUser(), addon, nil); m.NameID != "alice@example.test" {
		t.Errorf("probe chose %q", m.NameID)
	}
	// Without passthrough, unmapped claims are dropped.
	addon.PassthroughClaimsWithNoMapping = &no
	if got := attrs(buildAttributes(testUser(), addon, nil).Attributes); got["nickname"] != nil || got["mail"] == nil {
		t.Errorf("passthrough disabled: %v", got)
	}
}
