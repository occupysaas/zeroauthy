package seed_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const rbacSeed = `tenants:
- name: rbac
  domains: [rbac.example.test]
  resource_servers:
  - identifier: https://rbac.test
    enforce_policies: true
    token_dialect: rfc9068_profile_authz
    scopes:
    - value: read:x
  roles:
  - name: Editor
    description: seeded
    permissions:
    - resource_server_identifier: https://rbac.test
      permission_name: read:x
`

func TestRBACSeed(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(rbacSeed))
	if err != nil {
		t.Fatal(err)
	}
	f.Mode = seed.ModeCreateOnly
	if err := seed.Apply(ctx, st, f, nil, nil); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "rbac")
	api, _ := st.ResourceServers().GetByIdentifier(ctx, tn.ID, "https://rbac.test")
	if !api.EnforcePolicies || api.TokenDialect != "rfc9068_profile_authz" {
		t.Fatalf("API=%+v", api)
	}
	roles, err := st.RBAC().ListRoles(ctx, tn.ID, store.RBACPage{})
	if err != nil || len(roles.Items) != 1 {
		t.Fatalf("roles=%+v err=%v", roles, err)
	}
	role := roles.Items[0]
	perms, err := st.RBAC().RolePermissions(ctx, tn.ID, role.ID, store.RBACPage{})
	if err != nil || len(perms.Items) != 1 {
		t.Fatalf("permissions=%+v err=%v", perms, err)
	}
	role.Description = "operator edit"
	if err := st.RBAC().UpdateRole(ctx, &role); err != nil {
		t.Fatal(err)
	}
	if err := st.RBAC().ChangeRolePermissions(ctx, tn.ID, role.ID, false, []store.PermissionKey{{ResourceServerIdentifier: "https://rbac.test", PermissionName: "read:x"}}); err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(ctx, st, f, nil, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := st.RBAC().GetRole(ctx, tn.ID, role.ID)
	if got.Description != "operator edit" {
		t.Fatal("restart overwrote role")
	}
	perms, _ = st.RBAC().RolePermissions(ctx, tn.ID, role.ID, store.RBACPage{})
	if len(perms.Items) != 0 {
		t.Fatal("restart restored revoked permissions")
	}
	for _, text := range []string{strings.Replace(rbacSeed, "permission_name: read:x", "permission_name: missing", 1), strings.Replace(rbacSeed, "resource_server_identifier: https://rbac.test", "resource_server_identifier: https://missing.test", 1), strings.Replace(rbacSeed, "name: Editor", "name: ' '", 1), strings.Replace(rbacSeed, "rfc9068_profile_authz", "unknown", 1)} {
		if _, err := seed.Parse([]byte(text)); err == nil {
			t.Error("accepted invalid seed")
		}
	}
}
