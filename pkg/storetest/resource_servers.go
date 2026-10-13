package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newResourceServer(tenantID, id, identifier string) *store.ResourceServer {
	return &store.ResourceServer{
		TenantID:   tenantID,
		ID:         id,
		Identifier: identifier,
		Name:       "API " + id,
		Scopes: []store.Scope{
			{Value: "read:things", Description: "Read things"},
			{Value: "write:things", Description: "Write things"},
		},
		SigningAlg:         "RS256",
		TokenLifetime:      3600,
		AllowOfflineAccess: true,
		CreatedAt:          ts(0),
	}
}

func testResourceServers(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newResourceServer("ten_a", "rs1", "https://api.test")
		mustNoErr(t, s.ResourceServers().Create(ctx, want))

		got, err := s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		got, err = s.ResourceServers().GetByIdentifier(ctx, "ten_a", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.Scopes = want.Scopes[:1]
		want.Identifier = "https://api2.test"
		mustNoErr(t, s.ResourceServers().Update(ctx, want))
		_, err = s.ResourceServers().GetByIdentifier(ctx, "ten_a", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
		got, err = s.ResourceServers().GetByIdentifier(ctx, "ten_a", "https://api2.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		mustNoErr(t, s.ResourceServers().Delete(ctx, "ten_a", "rs1"))
		_, err = s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.ResourceServers().Delete(ctx, "ten_a", "rs1"), store.ErrNotFound)
		mustErrIs(t, s.ResourceServers().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("IdentifierUniquePerTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs1", "https://api.test")))
		mustErrIs(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs2", "https://api.test")), store.ErrConflict)
		mustErrIs(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs1", "https://other.test")), store.ErrConflict)
		// Same identifier in another tenant is fine.
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_b", "rs1", "https://api.test")))

		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "rs3", "https://three.test")))
		steal := newResourceServer("ten_a", "rs3", "https://api.test")
		mustErrIs(t, s.ResourceServers().Update(ctx, steal), store.ErrConflict)

		_, err := s.ResourceServers().GetByIdentifier(ctx, "ten_c", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newResourceServer("ten_a", "rs1", "https://api.test")
		mustNoErr(t, s.ResourceServers().Create(ctx, in))
		in.Scopes[0].Value = "mutated"
		got, err := s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustNoErr(t, err)
		mustEqual(t, got.Scopes[0].Value, "read:things")
	})
}
