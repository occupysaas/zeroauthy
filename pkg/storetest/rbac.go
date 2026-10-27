package storetest

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testRBAC catches lost permission sources, partial batch writes and stale
// rights surviving scope deletion. It runs unchanged against every driver.
func testRBAC(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := open(t, factory)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tid := range []string{"rbac-a", "rbac-b"} {
		must(s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
		api := newResourceServer(tid, "api", "https://rbac.test")
		api.IsSystem = false
		api.EnforcePolicies = true
		api.TokenDialect = "access_token_authz"
		must(s.ResourceServers().Create(ctx, api))
		must(s.Users().Create(ctx, &store.User{TenantID: tid, UserID: "u1"}))
	}
	r := s.RBAC()
	role := &store.Role{TenantID: "rbac-a", ID: "rol_a", Name: "Reader", Description: "read things"}
	must(r.CreateRole(ctx, role))
	role.Name = "changed"
	got, err := r.GetRole(ctx, "rbac-a", "rol_a")
	must(err)
	if got.Name != "Reader" {
		t.Fatal("input was not copied")
	}
	if _, err := r.GetRole(ctx, "rbac-b", "rol_a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	if err := r.CreateRole(ctx, &store.Role{TenantID: "rbac-a", ID: "rol_dup", Name: "Reader"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	must(r.CreateRole(ctx, &store.Role{TenantID: "rbac-a", ID: "rol_b", Name: "reader"}))
	key := store.PermissionKey{ResourceServerIdentifier: "https://rbac.test", PermissionName: "read:things"}
	must(r.ChangeRolePermissions(ctx, "rbac-a", "rol_a", true, []store.PermissionKey{key, key}))
	must(r.ChangeUserRoles(ctx, "rbac-a", "u1", true, []string{"rol_a"}))
	must(r.ChangeUserPermissions(ctx, "rbac-a", "u1", true, []store.PermissionKey{key}))
	p, err := r.UserPermissions(ctx, "rbac-a", "u1", store.RBACPage{})
	must(err)
	if len(p.Items) != 1 || len(p.Items[0].Sources) != 2 {
		t.Fatalf("sources %#v", p)
	}
	must(r.ChangeUserPermissions(ctx, "rbac-a", "u1", false, []store.PermissionKey{key}))
	snap, err := r.Snapshot(ctx, "rbac-a", "u1", key.ResourceServerIdentifier)
	must(err)
	if !reflect.DeepEqual(snap.Permissions, []string{"read:things"}) || !snap.API.EnforcePolicies || snap.API.TokenDialect != "access_token_authz" {
		t.Fatalf("snapshot %#v", snap)
	}
	other, err := r.Snapshot(ctx, "rbac-b", "u1", key.ResourceServerIdentifier)
	must(err)
	if len(other.Permissions) != 0 {
		t.Fatal("cross-tenant permission")
	}
	bad := key
	bad.PermissionName = "missing"
	if err := r.ChangeUserPermissions(ctx, "rbac-a", "u1", true, []store.PermissionKey{key, bad}); err == nil {
		t.Fatal("partial invalid batch accepted")
	}
	p, err = r.UserPermissions(ctx, "rbac-a", "u1", store.RBACPage{})
	must(err)
	if len(p.Items[0].Sources) != 1 {
		t.Fatal("invalid batch partly committed")
	}
	rollback := errors.New("rollback")
	if err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.RBAC().DeleteRole(ctx, "rbac-a", "rol_a"); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	_, err = r.GetRole(ctx, "rbac-a", "rol_a")
	must(err)
	page, err := r.ListRoles(ctx, "rbac-a", store.RBACPage{PerPage: 1, NameFilter: "READ"})
	must(err)
	if len(page.Items) != 1 || page.Total != 2 {
		t.Fatalf("page %#v", page)
	}
	api, err := s.ResourceServers().Get(ctx, "rbac-a", "api")
	must(err)
	scopes := api.Scopes
	api.Scopes = nil
	must(s.ResourceServers().Update(ctx, api))
	api.Scopes = scopes
	must(s.ResourceServers().Update(ctx, api))
	snap, err = r.Snapshot(ctx, "rbac-a", "u1", key.ResourceServerIdentifier)
	must(err)
	if len(snap.Permissions) != 0 {
		t.Fatal("recreated permission restored old right")
	}
	must(r.ChangeRolePermissions(ctx, "rbac-a", "rol_a", true, []store.PermissionKey{key}))
	must(s.Users().Delete(ctx, "rbac-a", "u1"))
	must(s.Users().Create(ctx, &store.User{TenantID: "rbac-a", UserID: "u1"}))
	members, err := r.RoleUsers(ctx, "rbac-a", "rol_a", store.RBACPage{})
	must(err)
	if len(members.Items) != 0 {
		t.Fatal("deleted member retained")
	}
	must(s.ResourceServers().Delete(ctx, "rbac-a", "api"))
	perms, err := r.RolePermissions(ctx, "rbac-a", "rol_a", store.RBACPage{})
	must(err)
	if len(perms.Items) != 0 {
		t.Fatal("deleted API permissions retained")
	}
	must(s.Tenants().Delete(ctx, "rbac-a"))
	roles, err := r.ListRoles(ctx, "rbac-a", store.RBACPage{})
	must(err)
	if len(roles.Items) != 0 {
		t.Fatal("tenant roles retained")
	}
}
