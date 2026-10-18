package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newOperator(tenantID, userID string, tenants ...string) *store.Operator {
	return &store.Operator{TenantID: tenantID, UserID: userID, Tenants: tenants, CreatedAt: ts(0), UpdatedAt: ts(0)}
}

func testOperators(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("UpsertGetListDelete", func(t *testing.T) {
		s := open(t, newStore)
		r := s.Operators()
		_, err := r.Get(ctx, "ten_sys", "auth0|a")
		mustErrIs(t, err, store.ErrNotFound)

		b := newOperator("ten_sys", "auth0|b", "*")
		a := newOperator("ten_sys", "auth0|a", "acme", "globex")
		other := newOperator("ten_other", "auth0|a", "*")
		for _, o := range []*store.Operator{b, a, other} {
			mustNoErr(t, r.Upsert(ctx, o))
		}
		got, err := r.Get(ctx, "ten_sys", "auth0|a")
		mustNoErr(t, err)
		mustEqual(t, got, a)

		list, err := r.List(ctx, "ten_sys")
		mustNoErr(t, err)
		mustEqual(t, list, []*store.Operator{a, b})

		// Upsert replaces Tenants and UpdatedAt and keeps CreatedAt.
		changed := newOperator("ten_sys", "auth0|a", "*")
		changed.CreatedAt, changed.UpdatedAt = ts(99*time.Second), ts(5*time.Second)
		mustNoErr(t, r.Upsert(ctx, changed))
		got, err = r.Get(ctx, "ten_sys", "auth0|a")
		mustNoErr(t, err)
		want := newOperator("ten_sys", "auth0|a", "*")
		want.UpdatedAt = ts(5 * time.Second)
		mustEqual(t, got, want)

		mustNoErr(t, r.Delete(ctx, "ten_sys", "auth0|a"))
		mustErrIs(t, r.Delete(ctx, "ten_sys", "auth0|a"), store.ErrNotFound)
		_, err = r.Get(ctx, "ten_sys", "auth0|a")
		mustErrIs(t, err, store.ErrNotFound)
		got, err = r.Get(ctx, "ten_other", "auth0|a")
		mustNoErr(t, err)
		mustEqual(t, got, other)

		list, err = r.List(ctx, "ten_none")
		mustNoErr(t, err)
		if len(list) != 0 {
			t.Fatalf("List of an empty tenant = %v", list)
		}
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		o := newOperator("ten_sys", "auth0|a", "*")
		mustNoErr(t, s.Operators().Upsert(ctx, o))
		o.Tenants[0] = "mutated"
		got, err := s.Operators().Get(ctx, "ten_sys", "auth0|a")
		mustNoErr(t, err)
		got.Tenants[0] = "mutated again"
		again, err := s.Operators().Get(ctx, "ten_sys", "auth0|a")
		mustNoErr(t, err)
		mustEqual(t, again.Tenants, []string{"*"})
	})
}

// testTenantsDelete fills two tenants with one entity of every kind, deletes
// one, and checks that only the other's data is left.
func testTenantsDelete(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("Missing", func(t *testing.T) {
		s := open(t, newStore)
		mustErrIs(t, s.Tenants().Delete(ctx, "ten_nope"), store.ErrNotFound)
	})

	t.Run("Cascades", func(t *testing.T) {
		s := open(t, newStore)
		fill := func(name string) *store.Tenant {
			tn := newTenant(name)
			id := tn.ID
			mustNoErr(t, s.Tenants().Create(ctx, tn))
			mustNoErr(t, s.Clients().Create(ctx, newClient(id, "app")))
			mustNoErr(t, s.ResourceServers().Create(ctx, newResourceServer(id, "rs_1", "https://api")))
			mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant(id, "cgr_1", "app", "https://api")))
			_, err := s.UserGrants().Upsert(ctx, newUserGrant(id, "ugr_1", "app", "auth0|u1", "https://api", "read"))
			mustNoErr(t, err)
			mustNoErr(t, s.SigningKeys().Create(ctx, newSigningKey(id, "kid1", store.KeyCurrent, 0)))
			mustNoErr(t, s.Connections().Create(ctx, newConnection(id, "con_1", "Database")))
			mustNoErr(t, s.Users().Create(ctx, newUser(id, "u1", "u1@example.test", "u1")))
			mustNoErr(t, s.Sessions().Create(ctx, newSession(id, "ses_1", "sh")))
			mustNoErr(t, s.AuthTransactions().Create(ctx, newAuthTransaction(id, "txn_1")))
			mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode(id, "ch")))
			mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest(id, "ph")))
			mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode(id, "dh", "uh")))
			mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken(id, "rt_1", "rh", "fam")))
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, newTicket(id, "prt_1", "th")))
			mustNoErr(t, s.Operators().Upsert(ctx, newOperator(id, "auth0|u1", "*")))
			return tn
		}
		gone, kept := fill("acme"), fill("globex")
		mustNoErr(t, s.Tenants().Delete(ctx, gone.ID))

		check := func(tenantID string, wantErr error) {
			t.Helper()
			errs := map[string]error{}
			_, errs["tenant"] = s.Tenants().Get(ctx, tenantID)
			_, errs["client"] = s.Clients().Get(ctx, tenantID, "app")
			_, errs["resource server"] = s.ResourceServers().Get(ctx, tenantID, "rs_1")
			_, errs["client grant"] = s.ClientGrants().Find(ctx, tenantID, "app", "https://api", store.SubjectTypeClient)
			_, errs["user grant"] = s.UserGrants().Find(ctx, tenantID, "app", "auth0|u1", "https://api")
			_, errs["connection"] = s.Connections().Get(ctx, tenantID, "con_1")
			_, errs["user"] = s.Users().Get(ctx, tenantID, "auth0|u1")
			_, errs["user login"] = s.Users().FindByLogin(ctx, tenantID, "Database", "u1@example.test")
			_, errs["session"] = s.Sessions().GetByTokenHash(ctx, tenantID, "sh")
			_, errs["transaction"] = s.AuthTransactions().Get(ctx, tenantID, "txn_1")
			_, errs["auth code"] = s.AuthCodes().Get(ctx, tenantID, "ch")
			_, errs["pushed request"] = s.PushedAuthRequests().Get(ctx, tenantID, "ph")
			_, errs["device code"] = s.DeviceCodes().Get(ctx, tenantID, "dh")
			_, errs["refresh token"] = s.RefreshTokens().GetByTokenHash(ctx, tenantID, "rh")
			_, errs["reset ticket"] = s.PasswordResetTickets().GetByTokenHash(ctx, tenantID, "th")
			_, errs["operator"] = s.Operators().Get(ctx, tenantID, "auth0|u1")
			for what, err := range errs {
				if wantErr == nil && err != nil {
					t.Errorf("%s of %s: %v", what, tenantID, err)
				}
				if wantErr != nil && !errors.Is(err, wantErr) {
					t.Errorf("%s of %s: err = %v, want %v", what, tenantID, err, wantErr)
				}
			}
			keys, err := s.SigningKeys().List(ctx, tenantID)
			mustNoErr(t, err)
			if (wantErr == nil) != (len(keys) == 1) {
				t.Errorf("signing keys of %s: %d", tenantID, len(keys))
			}
		}
		check(gone.ID, store.ErrNotFound)
		check(kept.ID, nil)
		_, err := s.Tenants().GetByDomain(ctx, gone.Domains[0])
		mustErrIs(t, err, store.ErrNotFound)

		// The name, domains and keys are free again.
		again := fill("acme")
		got, err := s.Tenants().GetByDomain(ctx, gone.Domains[0])
		mustNoErr(t, err)
		mustEqual(t, got.ID, again.ID)
		list, err := s.Tenants().List(ctx)
		mustNoErr(t, err)
		mustEqual(t, len(list), 2)
	})

	t.Run("Flags", func(t *testing.T) {
		s := open(t, newStore)
		want := newTenant("system")
		want.Reserved, want.Seeded, want.Origin = true, true, store.OriginAPI
		mustNoErr(t, s.Tenants().Create(ctx, want))
		got, err := s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)
		want.Reserved, want.Seeded, want.Origin = false, false, ""
		mustNoErr(t, s.Tenants().Update(ctx, want))
		got, err = s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)
	})
}
