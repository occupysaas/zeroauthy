package storetest

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func testGlobalRevocationState(t *testing.T, factory Factory) {
	s := open(t, factory)
	ctx := context.Background()
	mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: "ten_a", Name: "a"}))
	mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: "ten_b", Name: "b"}))
	repo, ok := s.(store.GlobalRevocationStore)
	if !ok {
		t.Fatal("missing global revocation repository")
	}
	now := time.Now().UTC()
	exp := now.Add(time.Minute)
	mustNoErr(t, repo.UseGlobalRevocationJTI(ctx, "ten_a", "conn", "unique", exp, now))
	mustErrIs(t, repo.UseGlobalRevocationJTI(ctx, "ten_a", "conn", "unique", exp, now), store.ErrConflict)
	mustNoErr(t, repo.UseGlobalRevocationJTI(ctx, "ten_b", "conn", "unique", exp, now))
	mustNoErr(t, repo.UseGlobalRevocationJTI(ctx, "ten_a", "other", "unique", exp, now))
	mustErrIs(t, s.WithTx(ctx, func(tx store.Store) error {
		r := tx.(store.GlobalRevocationStore)
		mustNoErr(t, r.UseGlobalRevocationJTI(ctx, "ten_a", "conn", "rollback", exp, now))
		return store.ErrConflict
	}), store.ErrConflict)
	mustNoErr(t, repo.UseGlobalRevocationJTI(ctx, "ten_a", "conn", "rollback", exp, now))
	n, err := repo.PurgeGlobalRevocationJTIs(ctx, now.Add(time.Minute), 2)
	mustNoErr(t, err)
	mustEqual(t, n, 2)
	n, err = repo.PurgeGlobalRevocationJTIs(ctx, now.Add(time.Minute), 10)
	mustNoErr(t, err)
	mustEqual(t, n, 2)
	mustNoErr(t, s.Connections().Create(ctx, &store.Connection{TenantID: "ten_a", ID: "conn", Name: "Enterprise", Strategy: "oidc"}))
	u := &store.User{TenantID: "ten_a", UserID: "auth0|owner", Email: "primary@example.test", Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "owner"}, {Connection: "Enterprise", Provider: "oidc", UserID: "Enterprise|subject", ProfileData: map[string]any{"email": "linked@example.test"}}}}
	mustNoErr(t, s.Users().Create(ctx, u))
	got, err := repo.FindByFederatedEmail(ctx, "ten_a", "conn", "linked@example.test")
	mustNoErr(t, err)
	mustEqual(t, got.UserID, u.UserID)
	for _, q := range []struct{ tenant, conn, email string }{{"ten_b", "conn", "linked@example.test"}, {"ten_a", "other", "linked@example.test"}, {"ten_a", "conn", "primary@example.test"}} {
		_, err := repo.FindByFederatedEmail(ctx, q.tenant, q.conn, q.email)
		mustErrIs(t, err, store.ErrNotFound)
	}
}
