package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testUserDelete pins Users.Delete: the user goes with everything that names
// it (sessions, refresh tokens, grants, reset tickets, password history,
// auth codes and device codes); other users' rows, in the same tenant or
// another, stay.
func testUserDelete(t *testing.T, newStore Factory) {
	ctx := context.Background()

	seed := func(t *testing.T, s store.Store, tenant string, ids ...string) {
		t.Helper()
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tenant, "con-"+tenant, "Database")))
		for _, id := range ids {
			u := newUser(tenant, id, id+"@x.test", "name-"+id)
			mustNoErr(t, s.Users().Create(ctx, u))
			uid := u.UserID
			sess := newSession(tenant, "sess-"+id, "sh-"+id)
			sess.UserID = uid
			mustNoErr(t, s.Sessions().Create(ctx, sess))
			rt := newRefreshToken(tenant, "rt-"+id, "rh-"+id, "fam-"+id)
			rt.UserID = uid
			mustNoErr(t, s.RefreshTokens().Create(ctx, rt))
			_, err := s.UserGrants().Upsert(ctx, newUserGrant(tenant, "ug-"+id, "spa", uid, "https://api.test", "read"))
			mustNoErr(t, err)
			tk := newTicket(tenant, "tk-"+id, "th-"+id)
			tk.UserID, tk.Connection = uid, "Database"
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, tk))
			mustNoErr(t, s.PasswordHistories().Add(ctx, tenant, uid, []byte("hash-"+id), 5))
			mustNoErr(t, s.Operators().Upsert(ctx, newOperator(tenant, uid, "*")))
			ac := newAuthCode(tenant, "ac-"+id)
			ac.UserID = uid
			mustNoErr(t, s.AuthCodes().Create(ctx, ac))
			dc := newDeviceCode(tenant, "dc-"+id, "uc-"+id)
			mustNoErr(t, s.DeviceCodes().Create(ctx, dc))
			_, err = s.DeviceCodes().Decide(ctx, tenant, "dc-"+id,
				store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: uid, GrantedScopes: []string{"openid"}})
			mustNoErr(t, err)
		}
	}
	type left struct{ User, Session, Token, Grant, Ticket, History, AuthCode, DeviceCode, Operator bool }
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
	all := left{true, true, true, true, true, true, true, true, true}

	t.Run("Cascade", func(t *testing.T) {
		s := open(t, newStore)
		seed(t, s, "ten_a", "u1", "u2")
		seed(t, s, "ten_b", "u1")
		mustNoErr(t, s.Users().Delete(ctx, "ten_a", "auth0|u1"))
		mustEqual(t, probe(t, s, "ten_a", "u1"), left{})
		mustEqual(t, probe(t, s, "ten_a", "u2"), all)
		mustEqual(t, probe(t, s, "ten_b", "u1"), all)
		// Logins are free again.
		_, err := s.Users().FindByLogin(ctx, "ten_a", "Database", "u1@x.test")
		mustErrIs(t, err, store.ErrNotFound)
		got, err := s.Users().FindByEmail(ctx, "ten_a", "u1@x.test")
		mustNoErr(t, err)
		mustEqual(t, len(got), 0)
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "u1@x.test", "name-u1")))
	})

	t.Run("OperatorRow", func(t *testing.T) {
		s := open(t, newStore)
		seed(t, s, "ten_a", "u1", "u2")
		mustNoErr(t, s.Users().Delete(ctx, "ten_a", "auth0|u1"))
		_, err := s.Operators().Get(ctx, "ten_a", "auth0|u1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Operators().Get(ctx, "ten_a", "auth0|u2")
		mustNoErr(t, err)
	})

	t.Run("ConsumedAuthCodeGoesToo", func(t *testing.T) {
		s := open(t, newStore)
		seed(t, s, "ten_a", "u1")
		_, err := s.AuthCodes().Consume(ctx, "ten_a", "ac-u1", ts(time.Second))
		mustNoErr(t, err)
		mustNoErr(t, s.Users().Delete(ctx, "ten_a", "auth0|u1"))
		mustEqual(t, probe(t, s, "ten_a", "u1"), left{})
	})

	t.Run("Unknown", func(t *testing.T) {
		s := open(t, newStore)
		seed(t, s, "ten_a", "u1")
		mustErrIs(t, s.Users().Delete(ctx, "ten_a", "auth0|missing"), store.ErrNotFound)
		mustErrIs(t, s.Users().Delete(ctx, "ten_b", "auth0|u1"), store.ErrNotFound)
		mustEqual(t, probe(t, s, "ten_a", "u1"), all)
		mustNoErr(t, s.Users().Delete(ctx, "ten_a", "auth0|u1"))
		mustErrIs(t, s.Users().Delete(ctx, "ten_a", "auth0|u1"), store.ErrNotFound)
	})

	t.Run("InTx", func(t *testing.T) {
		s := open(t, newStore)
		seed(t, s, "ten_a", "u1", "u2")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Users().Delete(ctx, "ten_a", "auth0|u1"); err != nil {
				return err
			}
			return context.Canceled
		})
		mustErrIs(t, err, context.Canceled)
		mustEqual(t, probe(t, s, "ten_a", "u1"), all)
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error { return tx.Users().Delete(ctx, "ten_a", "auth0|u1") }))
		mustEqual(t, probe(t, s, "ten_a", "u1"), left{})
		mustEqual(t, probe(t, s, "ten_a", "u2"), all)
	})
}
