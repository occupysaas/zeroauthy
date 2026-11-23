package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// TestGroupRolesInTokens is Plan 37c Review Focus 3: adding a member to a
// group with a role puts the role's permissions in the next token's
// snapshot; removing the member takes them out. Organization group roles
// apply only in that organization.
func TestGroupRolesInTokens(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	tid, uid, api := "ten_g", "samlp|corp|u1", "https://api.group.test"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: "g"}))
	must(st.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: tid, ID: "rs", Identifier: api, Name: "API", EnforcePolicies: true, TokenDialect: "access_token_authz",
		Scopes: []store.Scope{{Value: "read:x"}, {Value: "write:x"}}, SigningAlg: "RS256", TokenLifetime: 3600}))
	must(st.Connections().Create(ctx, &store.Connection{TenantID: tid, ID: "con", Name: "corp", Strategy: "samlp"}))
	must(st.Users().Create(ctx, &store.User{TenantID: tid, UserID: uid, Identities: []store.Identity{{Connection: "corp", Provider: "samlp", UserID: "corp|u1"}}}))
	r := st.RBAC()
	must(r.CreateRole(ctx, &store.Role{TenantID: tid, ID: "rol_read", Name: "Reader"}))
	must(r.CreateRole(ctx, &store.Role{TenantID: tid, ID: "rol_write", Name: "Writer"}))
	must(r.ChangeRolePermissions(ctx, tid, "rol_read", true, []store.PermissionKey{{ResourceServerIdentifier: api, PermissionName: "read:x"}}))
	must(r.ChangeRolePermissions(ctx, tid, "rol_write", true, []store.PermissionKey{{ResourceServerIdentifier: api, PermissionName: "write:x"}}))
	d := st.Directory()
	now := time.Now()
	must(d.CreateGroup(ctx, &store.Group{TenantID: tid, ID: "grp_aaaaaaaaaaaaaaaaaaaa", ConnectionID: "con", Name: "Eng", CreatedAt: now, UpdatedAt: now}))
	must(d.AddGroupRoles(ctx, tid, "grp_aaaaaaaaaaaaaaaaaaaa", "", []string{"rol_read"}))
	perms := func(org string) []string {
		t.Helper()
		snap, err := store.OrganizationAuthorizationSnapshot(ctx, st, tid, uid, org, api)
		must(err)
		return snap.Permissions
	}
	if got := perms(""); slices.Contains(got, "read:x") {
		t.Fatalf("permission before membership: %v", got)
	}
	must(d.UpdateGroupMembers(ctx, tid, "grp_aaaaaaaaaaaaaaaaaaaa", []string{uid}, nil, false, now))
	if got := perms(""); !slices.Equal(got, []string{"read:x"}) {
		t.Fatalf("group role not in the snapshot: %v", got)
	}
	// Organization group roles apply in that organization only.
	must(st.Organizations().Create(ctx, &store.Organization{TenantID: tid, ID: "org_abcdefghijklmnop", Name: "acme", CreatedAt: now}, nil))
	must(st.Organizations().AddMembers(ctx, tid, "org_abcdefghijklmnop", []string{uid}))
	must(d.AddGroupRoles(ctx, tid, "grp_aaaaaaaaaaaaaaaaaaaa", "org_abcdefghijklmnop", []string{"rol_write"}))
	if got := perms("org_abcdefghijklmnop"); !slices.Equal(got, []string{"read:x", "write:x"}) {
		t.Fatalf("organization snapshot %v", got)
	}
	if got := perms(""); slices.Contains(got, "write:x") {
		t.Fatalf("organization group role leaked outside the organization: %v", got)
	}
	must(d.UpdateGroupMembers(ctx, tid, "grp_aaaaaaaaaaaaaaaaaaaa", nil, []string{uid}, false, now))
	if got := perms("org_abcdefghijklmnop"); len(got) != 0 {
		t.Fatalf("permissions after leaving the group: %v", got)
	}
}
