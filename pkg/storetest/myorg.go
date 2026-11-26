package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testMyOrg is Plan 42b (my_org.v1): one configuration per client, role
// visibility, transactional rollback, and deletion with the client, the
// role and the tenant.
func testMyOrg(t *testing.T, factory Factory) {
	s := open(t, factory)
	ctx := context.Background()
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("b")))
	for _, tid := range []string{"ten_a", "ten_b"} {
		mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: tid, ClientID: "app", Name: "App", AppType: store.AppTypeSPA}))
		mustNoErr(t, s.Clients().Create(ctx, &store.Client{TenantID: tid, ClientID: "app2", Name: "App 2", AppType: store.AppTypeSPA}))
		mustNoErr(t, s.RBAC().CreateRole(ctx, &store.Role{TenantID: tid, ID: "rol_1", Name: "Admin"}))
		mustNoErr(t, s.RBAC().CreateRole(ctx, &store.Role{TenantID: tid, ID: "rol_2", Name: "Member"}))
	}
	repo, err := store.MyOrg(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(tid, cid, doc string) *store.MyOrgClientConfig {
		return &store.MyOrgClientConfig{TenantID: tid, ClientID: cid, Doc: []byte(doc)}
	}
	mustErrIs(t, repo.PutMyOrgClientConfig(ctx, cfg("ten_a", "", `{}`)), store.ErrInvalid)
	mustNoErr(t, repo.PutMyOrgClientConfig(ctx, cfg("ten_a", "app", `{"a":1}`)))
	mustNoErr(t, repo.PutMyOrgClientConfig(ctx, cfg("ten_a", "app", `{"a":2}`)))
	mustNoErr(t, repo.PutMyOrgClientConfig(ctx, cfg("ten_b", "app", `{"b":1}`)))
	got, err := repo.GetMyOrgClientConfig(ctx, "ten_a", "app")
	mustNoErr(t, err)
	mustEqual(t, string(got.Doc), `{"a":2}`)
	_, err = repo.GetMyOrgClientConfig(ctx, "ten_a", "app2")
	mustErrIs(t, err, store.ErrNotFound)
	mustNoErr(t, repo.DeleteMyOrgClientConfig(ctx, "ten_a", "app2"))

	mustNoErr(t, repo.SetMyOrgRoleVisible(ctx, "ten_a", "rol_2", true))
	mustNoErr(t, repo.SetMyOrgRoleVisible(ctx, "ten_a", "rol_1", true))
	mustNoErr(t, repo.SetMyOrgRoleVisible(ctx, "ten_a", "rol_1", true))
	mustNoErr(t, repo.SetMyOrgRoleVisible(ctx, "ten_b", "rol_1", true))
	roles, err := repo.ListMyOrgVisibleRoles(ctx, "ten_a")
	mustNoErr(t, err)
	mustEqual(t, len(roles), 2)
	mustEqual(t, roles[0], "rol_1")
	mustNoErr(t, repo.SetMyOrgRoleVisible(ctx, "ten_a", "rol_2", false))
	mustNoErr(t, repo.SetMyOrgRoleVisible(ctx, "ten_a", "rol_2", false))
	roles, _ = repo.ListMyOrgVisibleRoles(ctx, "ten_a")
	mustEqual(t, len(roles), 1)
	mustErrIs(t, repo.SetMyOrgRoleVisible(ctx, "ten_a", "rol_missing", true), store.ErrNotFound)

	// A failed transaction leaves nothing behind.
	mustErrIs(t, s.WithTx(ctx, func(tx store.Store) error {
		r, err := store.MyOrg(ctx, tx)
		if err != nil {
			return err
		}
		if err := r.PutMyOrgClientConfig(ctx, cfg("ten_a", "app2", `{"tx":1}`)); err != nil {
			return err
		}
		if err := r.SetMyOrgRoleVisible(ctx, "ten_a", "rol_2", true); err != nil {
			return err
		}
		return store.ErrConflict
	}), store.ErrConflict)
	_, err = repo.GetMyOrgClientConfig(ctx, "ten_a", "app2")
	mustErrIs(t, err, store.ErrNotFound)
	roles, _ = repo.ListMyOrgVisibleRoles(ctx, "ten_a")
	mustEqual(t, len(roles), 1)

	// Cascades.
	mustNoErr(t, s.Clients().Delete(ctx, "ten_a", "app"))
	_, err = repo.GetMyOrgClientConfig(ctx, "ten_a", "app")
	mustErrIs(t, err, store.ErrNotFound)
	mustNoErr(t, s.RBAC().DeleteRole(ctx, "ten_a", "rol_1"))
	roles, _ = repo.ListMyOrgVisibleRoles(ctx, "ten_a")
	mustEqual(t, len(roles), 0)
	mustNoErr(t, s.Tenants().Delete(ctx, "ten_b"))
	_, err = repo.GetMyOrgClientConfig(ctx, "ten_b", "app")
	mustErrIs(t, err, store.ErrNotFound)
	roles, _ = repo.ListMyOrgVisibleRoles(ctx, "ten_b")
	mustEqual(t, len(roles), 0)
}
