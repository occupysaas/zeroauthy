package mgmt_test

import (
	"context"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// Activating the My Organization API (Plan 42b) creates the system API
// with Auth0's settings; deleting it deactivates.
func TestActivateMyOrgAPI(t *testing.T) {
	ctx := context.Background()
	e := newRSEnv(t)
	id := tenant.MyOrgIdentifier(e.tn)
	out := e.mustCreate(t, map[string]any{"identifier": id, "name": "other"})
	if out["is_system"] != true || out["name"] != tenantsetup.MyOrgAPIName || out["token_lifetime"] != float64(600) || out["enforce_policies"] != true {
		t.Fatalf("created %v", out)
	}
	sta, _ := out["subject_type_authorization"].(map[string]any)
	if sta["user"].(map[string]any)["policy"] != "require_client_grant" || sta["client"].(map[string]any)["policy"] != "deny_all" {
		t.Fatalf("policies %v", sta)
	}
	got := scopeValues(out["scopes"])
	for _, s := range []string{"read:my_org:configuration", "read:my_org:details", "update:my_org:details", "read:my_org:members", "delete:my_org:memberships",
		"read:my_org:member_roles", "create:my_org:member_roles", "delete:my_org:member_roles", "read:my_org:member_invitations",
		"create:my_org:member_invitations", "delete:my_org:member_invitations", "read:my_org:user_stores"} {
		if !slices.Contains(got, s) {
			t.Errorf("scope %s missing", s)
		}
	}
	if rec, _ := e.create(t, map[string]any{"identifier": id}); rec.Code != 409 {
		t.Fatalf("second activation = %d", rec.Code)
	}
	if err := tenantsetup.ValidateManagementAPIIdentity(ctx, e.st, e.tn, baseDomain); err != nil {
		t.Fatal(err)
	}
	api, err := e.st.ResourceServers().GetByIdentifier(ctx, e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	// The Deploy CLI's system-API update; the lifetime stays fixed.
	if rec, out := e.patch(t, api.ID, map[string]any{"token_lifetime": 600, "skip_consent_for_verifiable_first_party_clients": true}); rec.Code != 200 || out["enforce_policies"] != true {
		t.Fatalf("Deploy CLI update = %d %v", rec.Code, out)
	}
	if rec, _ := e.patch(t, api.ID, map[string]any{"token_lifetime": 3600}); rec.Code != 400 {
		t.Fatalf("lifetime change = %d", rec.Code)
	}
	if rec, _ := e.patch(t, api.ID, map[string]any{"enforce_policies": false}); rec.Code != 400 {
		t.Fatalf("RBAC off = %d", rec.Code)
	}
	if rec := e.del(t, e.tn, api.ID); rec.Code != 204 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if _, err := e.st.ResourceServers().GetByIdentifier(ctx, e.tn.ID, id); err != store.ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
}

// Applications carry Auth0's my_organization_configuration (LR42b-4).
func TestClientMyOrgConfiguration(t *testing.T) {
	e := newClientsEnv(t)
	cfg := map[string]any{"allowed_strategies": []any{"oidc"}, "connection_deletion_behavior": "allow", "enforce_permission_ceiling": true}
	out := e.mustCreate(t, map[string]any{"name": "Admin portal", "app_type": "spa", "my_organization_configuration": cfg})
	got, _ := out["my_organization_configuration"].(map[string]any)
	if got["enforce_permission_ceiling"] != true || got["enforce_self_assignment_restriction"] != false || got["connection_deletion_behavior"] != "allow" {
		t.Fatalf("created %v", out["my_organization_configuration"])
	}
	id := out["client_id"].(string)
	cfg["invitation_landing_client_id"] = id
	rec, out := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"my_organization_configuration": cfg})
	if rec.Code != 200 || out["my_organization_configuration"].(map[string]any)["invitation_landing_client_id"] != id {
		t.Fatalf("patch = %d %v", rec.Code, out)
	}
	for name, bad := range map[string]any{
		"missing strategies": map[string]any{"connection_deletion_behavior": "allow"},
		"unknown member":     map[string]any{"allowed_strategies": []any{}, "connection_deletion_behavior": "allow", "x": 1},
		"unknown landing":    map[string]any{"allowed_strategies": []any{}, "connection_deletion_behavior": "allow", "invitation_landing_client_id": "nope"},
	} {
		if rec, _ := e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"my_organization_configuration": bad}); rec.Code != 400 {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}
	rec, out = e.patch(t, m2mCaller(allClientScopes...), id, map[string]any{"my_organization_configuration": nil})
	if rec.Code != 200 || out["my_organization_configuration"] != nil {
		t.Fatalf("remove = %d %v", rec.Code, out["my_organization_configuration"])
	}
}
