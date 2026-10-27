package rbacrules

import (
	"slices"
	"testing"
)

func TestRBACInventory(t *testing.T) {
	want := map[string][]string{
		"GET /api/v2/roles":                     {"read:roles"},
		"POST /api/v2/roles":                    {"create:roles"},
		"GET /api/v2/roles/{id}":                {"read:roles"},
		"PATCH /api/v2/roles/{id}":              {"update:roles"},
		"DELETE /api/v2/roles/{id}":             {"delete:roles"},
		"GET /api/v2/roles/{id}/permissions":    {"read:roles"},
		"POST /api/v2/roles/{id}/permissions":   {"update:roles"},
		"DELETE /api/v2/roles/{id}/permissions": {"update:roles"},
		"GET /api/v2/roles/{id}/users":          {"read:users", "read:roles", "read:role_members"},
		"POST /api/v2/roles/{id}/users":         {"update:roles", "create:role_members"},
		"GET /api/v2/users/{id}/roles":          {"read:users", "read:roles", "read:role_members"},
		"POST /api/v2/users/{id}/roles":         {"update:users", "create:role_members"},
		"DELETE /api/v2/users/{id}/roles":       {"update:users", "delete:role_members"},
		"GET /api/v2/users/{id}/permissions":    {"read:users"},
		"POST /api/v2/users/{id}/permissions":   {"update:users"},
		"DELETE /api/v2/users/{id}/permissions": {"update:users"},
	}
	got := Inventory()
	if len(got) != 16 {
		t.Fatalf("operations=%d, want 16", len(got))
	}
	for _, op := range got {
		key := op.Method + " " + op.Path
		scopes, ok := want[key]
		if !ok {
			t.Fatalf("unexpected or duplicate operation %s", key)
		}
		if !slices.Equal(op.RequiredScopes, scopes) {
			t.Errorf("%s scopes=%v want %v", key, op.RequiredScopes, scopes)
		}
		if op.ScopeMatch != "all" {
			t.Errorf("%s scopes must all be required", key)
		}
		if op.SourceURL == "" || op.Evidence != "documented" || op.ResponseShape == "" || op.SuccessStatus < 200 {
			t.Errorf("%s incomplete contract", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing operations %v", want)
	}
	m := InventoryMetadata()
	if !slices.Equal(m.Dialects, []string{"access_token", "access_token_authz", "rfc9068_profile", "rfc9068_profile_authz"}) {
		t.Fatalf("dialects=%v", m.Dialects)
	}
	for _, feature := range []string{"groups", "organization_roles", "role_list_checkpoint_ea", "effective_roles"} {
		if !slices.Contains(m.Deferred, feature) {
			t.Errorf("missing deferred %s", feature)
		}
	}
	if len(m.Rules) == 0 {
		t.Fatal("missing rules")
	}
	names := map[string]bool{}
	for _, rule := range m.Rules {
		names[rule.Name] = true
		if rule.Value == "" || (rule.SourceURL == "" && rule.Decision == "") {
			t.Errorf("rule %s has no value or provenance", rule.Name)
		}
		if rule.Evidence == "local-decision" && rule.Decision != "D-0052" {
			t.Errorf("rule %s has no local decision", rule.Name)
		}
	}
	for _, name := range []string{"effective_permissions", "direct_removal", "role_name", "role_description", "batch", "name_uniqueness", "role_user_checkpoint", "permission_sources", "cleanup", "rbac_off_authz", "refresh_ceiling", "snapshot_timing"} {
		if !names[name] {
			t.Errorf("missing rule %s", name)
		}
	}
}

func TestRBACInventoryReturnsIndependentValues(t *testing.T) {
	ops := Inventory()
	ops[0].RequiredScopes[0] = "changed"
	if Inventory()[0].RequiredScopes[0] != "read:roles" {
		t.Fatal("caller mutation changed inventory")
	}
	m := InventoryMetadata()
	m.Dialects[0] = "changed"
	if InventoryMetadata().Dialects[0] != "access_token" {
		t.Fatal("caller mutation changed metadata")
	}
}
