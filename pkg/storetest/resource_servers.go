package storetest

import (
	"context"
	"errors"
	"reflect"
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
		SigningAlg:          "RS256",
		TokenLifetime:       3600,
		TokenLifetimeForWeb: 1800,
		AllowOfflineAccess:  true,
		CreatedAt:           ts(0),

		SkipConsentForVerifiableFirstPartyClients: true,
		IsSystem: true,
	}
}

func testResourceServers(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("RenameSystemPreservesSettings", func(t *testing.T) {
		s := open(t, newStore)
		want := newResourceServer("ten_a", "system", "https://api.test")
		want.Name = "old name"
		if err := s.ResourceServers().Create(ctx, want); err != nil {
			t.Fatal(err)
		}
		ordinary := newResourceServer("ten_a", "ordinary", "https://ordinary.test")
		ordinary.IsSystem = false
		ordinary.Name = "old name"
		if err := s.ResourceServers().Create(ctx, ordinary); err != nil {
			t.Fatal(err)
		}
		if err := s.ResourceServers().RenameSystem(ctx, "ten_a", want.Identifier, "new name"); err != nil {
			t.Fatal(err)
		}
		if err := s.ResourceServers().RenameSystem(ctx, "ten_a", want.Identifier, "new name"); err != nil {
			t.Fatalf("repeated rename: %v", err)
		}
		got, err := s.ResourceServers().Get(ctx, "ten_a", "system")
		if err != nil {
			t.Fatal(err)
		}
		want.Name = "new name"
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("name-only rename: got %#v want %#v", got, want)
		}
		gotOrdinary, err := s.ResourceServers().Get(ctx, "ten_a", "ordinary")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotOrdinary, ordinary) {
			t.Fatalf("ordinary resource changed: %#v", gotOrdinary)
		}
		if err := s.ResourceServers().RenameSystem(ctx, "ten_a", ordinary.Identifier, "wrong"); err != store.ErrNotFound {
			t.Fatalf("ordinary rename error = %v", err)
		}
		if err := s.ResourceServers().RenameSystem(ctx, "ten_b", want.Identifier, "wrong"); err != store.ErrNotFound {
			t.Fatalf("cross-tenant rename error = %v", err)
		}
	})

	t.Run("RenameSystemTransactions", func(t *testing.T) {
		s := open(t, newStore)
		want := newResourceServer("ten_a", "tx-system", "https://tx-api.test")
		if err := s.ResourceServers().Create(ctx, want); err != nil {
			t.Fatal(err)
		}
		rollback := errors.New("roll back rename")
		if err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.ResourceServers().RenameSystem(ctx, "ten_a", want.Identifier, "uncommitted"); err != nil {
				return err
			}
			return rollback
		}); !errors.Is(err, rollback) {
			t.Fatalf("rollback error = %v", err)
		}
		got, err := s.ResourceServers().Get(ctx, "ten_a", want.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != want.Name {
			t.Fatalf("rolled-back rename persisted: %q", got.Name)
		}
		if err := s.WithTx(ctx, func(tx store.Store) error {
			return tx.ResourceServers().RenameSystem(ctx, "ten_a", want.Identifier, "committed")
		}); err != nil {
			t.Fatal(err)
		}
		got, err = s.ResourceServers().Get(ctx, "ten_a", want.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != "committed" {
			t.Fatalf("committed rename missing: %q", got.Name)
		}
	})

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

	t.Run("DeleteCascades", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "gone", "https://gone.test")))
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "kept", "https://kept.test")))
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_b", "gone", "https://gone.test")))
		for _, tn := range []string{"ten_a", "ten_b"} {
			mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant(tn, "cg_gone", "c1", "https://gone.test")))
			_, err := s.UserGrants().Upsert(ctx, newUserGrant(tn, "ug_gone", "c1", "auth0|u1", "https://gone.test", "read"))
			mustNoErr(t, err)
			rt := newRefreshToken(tn, "rt_gone", "h_gone", "f_gone")
			rt.Audience = "https://gone.test"
			mustNoErr(t, s.RefreshTokens().Create(ctx, rt))
		}
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg_kept", "c1", "https://kept.test")))
		_, err := s.UserGrants().Upsert(ctx, newUserGrant("ten_a", "ug_kept", "c1", "auth0|u1", "https://kept.test", "read"))
		mustNoErr(t, err)
		rt := newRefreshToken("ten_a", "rt_kept", "h_kept", "f_kept")
		rt.Audience = "https://kept.test"
		mustNoErr(t, s.RefreshTokens().Create(ctx, rt))

		mustNoErr(t, s.ResourceServers().Delete(ctx, "ten_a", "gone"))

		_, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://gone.test", store.SubjectTypeClient)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://gone.test")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h_gone")
		mustErrIs(t, err, store.ErrNotFound)
		// Other APIs, and the same identifier in another tenant, keep theirs.
		_, err = s.ClientGrants().Find(ctx, "ten_a", "c1", "https://kept.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://kept.test")
		mustNoErr(t, err)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h_kept")
		mustNoErr(t, err)
		_, err = s.ClientGrants().Find(ctx, "ten_b", "c1", "https://gone.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		_, err = s.UserGrants().Find(ctx, "ten_b", "c1", "auth0|u1", "https://gone.test")
		mustNoErr(t, err)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_b", "h_gone")
		mustNoErr(t, err)
	})

	t.Run("DeleteClearsDefaultAudience", func(t *testing.T) {
		s := open(t, newStore)
		for _, name := range []string{"a", "b"} {
			mustNoErr(t, s.Tenants().Create(ctx, newTenant(name)))
		}
		// ten_a's default audience is https://a.api.test; ten_b has the same
		// identifier as an ordinary API and its own default.
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "dflt", "https://a.api.test")))
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_a", "other", "https://other.test")))
		mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer("ten_b", "dflt", "https://a.api.test")))

		mustNoErr(t, s.ResourceServers().Delete(ctx, "ten_a", "other"))
		got, err := s.Tenants().Get(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got.DefaultAudience, "https://a.api.test")

		mustNoErr(t, s.ResourceServers().Delete(ctx, "ten_a", "dflt"))
		got, err = s.Tenants().Get(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, got.DefaultAudience, "")
		got, err = s.Tenants().Get(ctx, "ten_b")
		mustNoErr(t, err)
		mustEqual(t, got.DefaultAudience, "https://b.api.test")
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
