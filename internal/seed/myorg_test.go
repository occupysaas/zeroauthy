package seed

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const myOrgSeed = `
tenants:
  - name: acme
    domains: [login.acme.test]
    my_organization_api: {active: true}
    roles:
      - name: Org Admin
        my_organization_visible: true
        permissions: [{resource_server_identifier: "https://login.acme.test/my-org/", permission_name: "read:my_org:members"}]
      - {name: Member}
    clients:
      - client_id: portal
        app_type: spa
        callbacks: ["https://app.acme.test/cb"]
        my_organization_configuration: {allowed_strategies: [oidc], connection_deletion_behavior: allow, invitation_landing_client_id: portal, enforce_permission_ceiling: true}
    client_grants:
      - {client_id: portal, audience: "https://login.acme.test/my-org/", subject_type: user, scopes: ["read:my_org:members"]}
`

// Plan 42b: my_organization_api.active, visible roles with permissions on
// the API, application configurations and user grants.
func TestSeedMyOrganizationAPI(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(myOrgSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	api, err := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://login.acme.test/my-org/")
	if err != nil || !api.IsSystem || !api.EnforcePolicies {
		t.Fatalf("API %+v %v", api, err)
	}
	roles, _ := st.RBAC().ListRoles(ctx, tn.ID, store.RBACPage{PerPage: 10})
	byName := map[string]string{}
	for _, r := range roles.Items {
		byName[r.Name] = r.ID
	}
	repo, _ := store.MyOrg(ctx, st)
	visible, _ := repo.ListMyOrgVisibleRoles(ctx, tn.ID)
	if len(visible) != 1 || visible[0] != byName["Org Admin"] {
		t.Fatalf("visible %v (%v)", visible, byName)
	}
	perms, _ := st.RBAC().RolePermissions(ctx, tn.ID, byName["Org Admin"], store.RBACPage{PerPage: 10})
	if len(perms.Items) != 1 {
		t.Fatalf("permissions %+v", perms)
	}
	cfg, err := repo.GetMyOrgClientConfig(ctx, tn.ID, "portal")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(cfg.Doc, &doc)
	if doc["enforce_permission_ceiling"] != true || doc["invitation_landing_client_id"] != "portal" {
		t.Fatalf("config %v", doc)
	}
	if _, err := st.ClientGrants().Find(ctx, tn.ID, "portal", api.Identifier, store.SubjectTypeUser); err != nil {
		t.Fatal(err)
	}
	// Applying again is idempotent.
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
}

func TestSeedMyOrganizationAPIRefusals(t *testing.T) {
	for name, text := range map[string]string{
		"inactive":        strings.Replace(myOrgSeed, "my_organization_api: {active: true}", "my_organization_api: {active: false}", 1),
		"bad config":      strings.Replace(myOrgSeed, "connection_deletion_behavior: allow,", "connection_deletion_behavior: never,", 1),
		"unknown landing": strings.Replace(myOrgSeed, "invitation_landing_client_id: portal", "invitation_landing_client_id: nope", 1),
		"unknown scope":   strings.Replace(myOrgSeed, `permission_name: "read:my_org:members"`, `permission_name: "read:my_org:groups"`, 1), // an OpenAPI scope without operations (D-0221)
		"client grant":    strings.Replace(myOrgSeed, "subject_type: user", "subject_type: client", 1),
	} {
		f, err := Parse([]byte(text))
		if err == nil {
			err = Apply(context.Background(), memory.New(), f, fixedNow, testWrapper(t))
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
