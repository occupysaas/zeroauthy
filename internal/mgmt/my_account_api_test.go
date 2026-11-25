package mgmt_test

import (
	"context"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// Activating the My Account API (Plan 42a, LR42a-4) through the Management
// API and through tenantsetup gives the same system API; deleting it
// deactivates.
func TestActivateCreatesSystemAPI(t *testing.T) {
	ctx := context.Background()
	e := newRSEnv(t)
	id := tenant.MyAccountIdentifier(e.tn)
	if id == "" || id[len(id)-4:] != "/me/" {
		t.Fatalf("identifier %q", id)
	}
	// Other fields in the body are ignored: the system API's settings are fixed.
	out := e.mustCreate(t, map[string]any{"identifier": id, "name": "mine", "allow_offline_access": false})
	if out["is_system"] != true || out["name"] != tenantsetup.MyAccountAPIName || out["allow_offline_access"] != true {
		t.Fatalf("created %v", out)
	}
	sta, _ := out["subject_type_authorization"].(map[string]any)
	user, _ := sta["user"].(map[string]any)
	client, _ := sta["client"].(map[string]any)
	if user["policy"] != "require_client_grant" || client["policy"] != "deny_all" {
		t.Fatalf("subject_type_authorization %v", sta)
	}
	got := scopeValues(out["scopes"])
	for _, s := range []string{"read:me:factors", "read:me:authentication_methods", "create:me:authentication_methods", "update:me:authentication_methods", "delete:me:authentication_methods"} {
		if !slices.Contains(got, s) {
			t.Errorf("scope %s missing from %v", s, got)
		}
	}
	if rec, _ := e.create(t, map[string]any{"identifier": id}); rec.Code != 409 {
		t.Fatalf("second activation = %d %s", rec.Code, rec.Body)
	}
	viaSetup, err := tenantsetup.MyAccountAPI(ctx, e.st, e.tn, now)
	if err != nil || viaSetup.ID != out["id"] || !viaSetup.IsSystem || viaSetup.SubjectTypeAuthorization.User != store.PolicyRequireClientGrant {
		t.Fatalf("tenantsetup = %+v %v", viaSetup, err)
	}
	// The tenant's Management API identity check accepts the second system API.
	if err := tenantsetup.ValidateManagementAPIIdentity(ctx, e.st, e.tn, baseDomain); err != nil {
		t.Fatal(err)
	}
	// System settings stay fixed.
	if rec, _ := e.patch(t, viaSetup.ID, map[string]any{"scopes": []any{}}); rec.Code != 400 {
		t.Fatalf("patch scopes = %d", rec.Code)
	}
	// The fields the Deploy CLI (9.1.0) sends when it updates a system API.
	if rec, out := e.patch(t, viaSetup.ID, map[string]any{"token_lifetime": 3600, "skip_consent_for_verifiable_first_party_clients": true,
		"subject_type_authorization": map[string]any{"user": map[string]any{"policy": "require_client_grant"}, "client": map[string]any{"policy": "deny_all"}}}); rec.Code != 200 || out["token_lifetime"] != float64(3600) {
		t.Fatalf("Deploy CLI update = %d %v", rec.Code, out)
	}
	if rec := e.del(t, e.tn, viaSetup.ID); rec.Code != 204 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body)
	}
	if _, err := e.st.ResourceServers().GetByIdentifier(ctx, e.tn.ID, id); err != store.ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	// The Management API itself still cannot be deleted.
	if rec := e.del(t, e.tn, e.mapi.ID); rec.Code != 400 {
		t.Fatalf("delete Management API = %d", rec.Code)
	}
}
