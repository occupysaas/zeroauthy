package storetest

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testConnectionDelete pins Connections.Delete: the connection's users go
// with it, with their sessions, refresh tokens, grants, reset and verification tickets and
// password history, auth codes and device codes; the tenant's default directory is cleared when it names
// the connection; nothing of another connection or tenant is touched.
func testConnectionDelete(t *testing.T, newStore Factory) {
	ctx := context.Background()

	// seedTenant creates tenant name with connections "Database" (con1) and
	// "Other" (con2), plus per connection one user holding every kind of
	// dependent row.
	seedTenant := func(t *testing.T, s store.Store, tenant string) {
		t.Helper()
		tn := newTenant(tenant)
		tn.ID = tenant
		tn.DefaultDirectory = "Database"
		mustNoErr(t, s.Tenants().Create(ctx, tn))
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tenant, "con1", "Database")))
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tenant, "con2", "Other")))
		for _, sp := range []struct{ id, conn, tag string }{{"u1", "Database", "d"}, {"u2", "Database", "e"}, {"u3", "Other", "o"}} {
			u := newUser(tenant, sp.id, sp.id+"@x.test", "name-"+sp.id)
			u.Identities[0].Connection = sp.conn
			mustNoErr(t, s.Users().Create(ctx, u))
			uid := u.UserID
			sess := newSession(tenant, "sess-"+sp.id, "sh-"+sp.id)
			sess.UserID, sess.Connection = uid, sp.conn
			mustNoErr(t, s.Sessions().Create(ctx, sess))
			rt := newRefreshToken(tenant, "rt-"+sp.id, "rh-"+sp.id, "fam-"+sp.id)
			rt.UserID = uid
			mustNoErr(t, s.RefreshTokens().Create(ctx, rt))
			_, err := s.UserGrants().Upsert(ctx, newUserGrant(tenant, "ug-"+sp.id, "spa", uid, "https://api.test", "read"))
			mustNoErr(t, err)
			tk := newTicket(tenant, "tk-"+sp.id, "th-"+sp.id)
			tk.UserID, tk.Connection = uid, sp.conn
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, tk))
			vt := newVerificationTicket(tenant, "vt-"+sp.id, "vh-"+sp.id)
			vt.UserID, vt.Connection = uid, sp.conn
			mustNoErr(t, s.EmailVerificationTickets().Create(ctx, vt))
			mustNoErr(t, s.PasswordHistories().Add(ctx, tenant, uid, []byte("hash-"+sp.id), 5))
			mustNoErr(t, s.Operators().Upsert(ctx, newOperator(tenant, uid, "*")))
			ac := newAuthCode(tenant, "ac-"+sp.id)
			ac.UserID = uid
			mustNoErr(t, s.AuthCodes().Create(ctx, ac))
			mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode(tenant, "dc-"+sp.id, "uc-"+sp.id)))
			_, err = s.DeviceCodes().Decide(ctx, tenant, "dc-"+sp.id,
				store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: uid, GrantedScopes: []string{"openid"}})
			mustNoErr(t, err)
		}
	}
	// present reports which of the three users' rows still exist.
	type left struct{ User, Session, Token, Grant, Ticket, VerifyTicket, History, AuthCode, DeviceCode, Operator bool }
	probe := func(t *testing.T, s store.Store, tenant, id string) left {
		t.Helper()
		uid := "auth0|" + id
		var l left
		_, err := s.Users().Get(ctx, tenant, uid)
		l.User = err == nil
		_, err = s.Sessions().GetByTokenHash(ctx, tenant, "sh-"+id)
		l.Session = err == nil
		_, err = s.RefreshTokens().GetByTokenHash(ctx, tenant, "rh-"+id)
		l.Token = err == nil
		gs, err := s.UserGrants().ListByUser(ctx, tenant, uid)
		mustNoErr(t, err)
		l.Grant = len(gs) > 0
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, tenant, "th-"+id)
		l.Ticket = err == nil
		_, err = s.EmailVerificationTickets().GetByTokenHash(ctx, tenant, "vh-"+id)
		l.VerifyTicket = err == nil
		h, err := s.PasswordHistories().List(ctx, tenant, uid)
		mustNoErr(t, err)
		l.History = len(h) > 0
		_, err = s.AuthCodes().Get(ctx, tenant, "ac-"+id)
		l.AuthCode = err == nil
		_, err = s.DeviceCodes().Get(ctx, tenant, "dc-"+id)
		l.DeviceCode = err == nil
		_, err = s.Operators().Get(ctx, tenant, uid)
		l.Operator = err == nil
		return l
	}
	all := left{true, true, true, true, true, true, true, true, true, true}

	t.Run("Cascade", func(t *testing.T) {
		s := open(t, newStore)
		seedTenant(t, s, "ten_a")
		seedTenant(t, s, "ten_b")
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con1"))

		_, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Connections().GetByName(ctx, "ten_a", "Database")
		mustErrIs(t, err, store.ErrNotFound)
		mustEqual(t, probe(t, s, "ten_a", "u1"), left{})
		mustEqual(t, probe(t, s, "ten_a", "u2"), left{})
		// Logins are free again.
		_, err = s.Users().FindByLogin(ctx, "ten_a", "Database", "u1@x.test")
		mustErrIs(t, err, store.ErrNotFound)

		// The other connection, the other tenant and the tenant itself.
		mustEqual(t, probe(t, s, "ten_a", "u3"), all)
		mustEqual(t, probe(t, s, "ten_b", "u1"), all)
		mustEqual(t, probe(t, s, "ten_b", "u3"), all)
		_, err = s.Connections().Get(ctx, "ten_a", "con2")
		mustNoErr(t, err)
		_, err = s.Connections().Get(ctx, "ten_b", "con1")
		mustNoErr(t, err)
		_, err = s.Users().FindByLogin(ctx, "ten_a", "Other", "u3@x.test")
		mustNoErr(t, err)
		tn, err := s.Tenants().Get(ctx, "ten_b")
		mustNoErr(t, err)
		mustEqual(t, tn.DefaultDirectory, "Database")
	})

	t.Run("ClearsDefaultDirectory", func(t *testing.T) {
		s := open(t, newStore)
		seedTenant(t, s, "ten_a")
		seedTenant(t, s, "ten_b")
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con1"))
		tn, err := s.Tenants().Get(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, tn.DefaultDirectory, "")
		// Nothing else of the tenant changed.
		want := newTenant("ten_a")
		want.ID, want.DefaultDirectory = "ten_a", ""
		mustEqual(t, tn, want)
		tn, err = s.Tenants().Get(ctx, "ten_b")
		mustNoErr(t, err)
		mustEqual(t, tn.DefaultDirectory, "Database")
	})

	t.Run("KeepsDefaultDirectoryOfAnotherConnection", func(t *testing.T) {
		s := open(t, newStore)
		seedTenant(t, s, "ten_a")
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con2"))
		tn, err := s.Tenants().Get(ctx, "ten_a")
		mustNoErr(t, err)
		mustEqual(t, tn.DefaultDirectory, "Database")
		mustEqual(t, probe(t, s, "ten_a", "u3"), left{})
		mustEqual(t, probe(t, s, "ten_a", "u1"), all)
	})

	t.Run("NameIsFreeAgain", func(t *testing.T) {
		s := open(t, newStore)
		seedTenant(t, s, "ten_a")
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con1"))
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con3", "Database")))
		u := newUser("ten_a", "u1", "u1@x.test", "name-u1")
		mustNoErr(t, s.Users().Create(ctx, u))
	})

	t.Run("Unknown", func(t *testing.T) {
		s := open(t, newStore)
		seedTenant(t, s, "ten_a")
		mustErrIs(t, s.Connections().Delete(ctx, "ten_a", "missing"), store.ErrNotFound)
		mustErrIs(t, s.Connections().Delete(ctx, "ten_zz", "con1"), store.ErrNotFound)
		mustErrIs(t, s.Connections().Delete(ctx, "ten_b", "con1"), store.ErrNotFound)
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con1"))
		mustErrIs(t, s.Connections().Delete(ctx, "ten_a", "con1"), store.ErrNotFound)
		mustEqual(t, probe(t, s, "ten_a", "u3"), all)
	})

	t.Run("NoUsers", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con1", "Lonely")))
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con1"))
		_, err := s.Connections().Get(ctx, "ten_a", "con1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("UserWithoutLoginIdentifiers", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ten_a", "con1", "Database")))
		u := newUser("ten_a", "u1", "", "")
		mustNoErr(t, s.Users().Create(ctx, u))
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con1"))
		_, err := s.Users().Get(ctx, "ten_a", u.UserID)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("InTx", func(t *testing.T) {
		s := open(t, newStore)
		seedTenant(t, s, "ten_a")
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			return tx.Connections().Delete(ctx, "ten_a", "con1")
		}))
		mustEqual(t, probe(t, s, "ten_a", "u1"), left{})
		// A rolled back delete leaves everything.
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Connections().Delete(ctx, "ten_a", "con2"); err != nil {
				return err
			}
			return context.Canceled
		})
		mustErrIs(t, err, context.Canceled)
		mustEqual(t, probe(t, s, "ten_a", "u3"), all)
		_, err = s.Connections().Get(ctx, "ten_a", "con2")
		mustNoErr(t, err)
	})

}
