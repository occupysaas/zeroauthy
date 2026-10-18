package storetest

import (
	"context"
	"testing"
	"time"

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

		SkipConsentForVerifiableFirstPartyClients: true,
		IsSystem: true,
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
		want.Origin = store.OriginAPI
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

	t.Run("ConsentAndPolicies", func(t *testing.T) {
		s := open(t, newStore)
		want := newResourceServer("ten_a", "rs1", "https://api.test")
		want.SkipConsentForVerifiableFirstPartyClients = false
		want.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyRequireClientGrant, Client: store.PolicyDenyAll}
		mustNoErr(t, s.ResourceServers().Create(ctx, want))
		got, err := s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyDenyAll}
		mustNoErr(t, s.ResourceServers().Update(ctx, want))
		got, err = s.ResourceServers().Get(ctx, "ten_a", "rs1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
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

	t.Run("List", func(t *testing.T) {
		s := open(t, newStore)
		// Creation order: CreatedAt, then ID (rs_B, rs_a tie on time and
		// sort by byte order).
		for _, c := range []struct {
			id  string
			sec int
		}{{"rs_z", 1}, {"rs_a", 3}, {"rs_B", 3}, {"rs_m", 2}} {
			rs := newResourceServer("ten_a", c.id, "https://"+c.id)
			rs.CreatedAt = ts(time.Duration(c.sec) * time.Second)
			if c.id == "rs_m" {
				rs.Origin = store.OriginAPI
			}
			mustNoErr(t, s.ResourceServers().Create(ctx, rs))
		}
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_b", "rs_other", "https://other")))

		got, err := s.ResourceServers().List(ctx, "ten_a")
		mustNoErr(t, err)
		var ids []string
		for _, rs := range got {
			ids = append(ids, rs.ID)
		}
		mustEqual(t, ids, []string{"rs_z", "rs_m", "rs_B", "rs_a"})
		mustEqual(t, got[1].Origin, store.OriginAPI)
		mustEqual(t, got[0].Origin, "")
		mustEqual(t, got[0], func() *store.ResourceServer {
			w := newResourceServer("ten_a", "rs_z", "https://rs_z")
			w.CreatedAt = ts(time.Second)
			return w
		}())

		got[0].Scopes[0].Value = "mutated"
		again, err := s.ResourceServers().List(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, again[0].Scopes[0].Value, "read:things")

		got, err = s.ResourceServers().List(ctx, "ten_b")
		mustNoErr(t, err)
		mustEqual(t, len(got), 1)
		got, err = s.ResourceServers().List(ctx, "ten_none")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
	})
}
