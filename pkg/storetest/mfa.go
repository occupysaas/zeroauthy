package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// MFA runs the storage contract against a fresh driver for each case.
func MFA(t *testing.T, factory Factory) {
	ctx := context.Background()
	now := ts(0)
	setup := func(t *testing.T) store.Store {
		s := open(t, factory)
		for _, tid := range []string{"a", "b"} {
			tenant := newTenant(tid)
			tenant.ID = tid
			mustNoErr(t, s.Tenants().Create(ctx, tenant))
			mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: tid, UserID: "u"}))
		}
		mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: "a", UserID: "auth0|u1"}))
		mustNoErr(t, s.Clients().Create(ctx, newClient("a", "c")))
		return s
	}
	t.Run("MFARejectCrossTenantReferences", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: "b", UserID: "other"}))
		mustNoErr(t, s.Clients().Create(ctx, newClient("b", "other-client")))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "b", UserID: "other", ID: "other-factor"}))
		mustErrIs(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "other", ID: "x"}), store.ErrNotFound)
		mustErrIs(t, s.MFA().CreateMFAToken(ctx, &store.MFAToken{TenantID: "a", UserID: "other", ClientID: "c", Hash: "x"}), store.ErrNotFound)
		mustErrIs(t, s.MFA().CreateMFAToken(ctx, &store.MFAToken{TenantID: "a", UserID: "u", ClientID: "other-client", Hash: "x"}), store.ErrNotFound)
		mustErrIs(t, s.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", UserID: "other", ID: "x"}), store.ErrNotFound)
		mustErrIs(t, s.MFA().CreateChallenge(ctx, &store.MFAChallenge{TenantID: "a", UserID: "u", AuthenticatorID: "other-factor", ID: "x"}), store.ErrNotFound)
		mustErrIs(t, s.MFA().CreateTicket(ctx, &store.EnrollmentTicket{TenantID: "a", UserID: "other", Hash: "x"}), store.ErrNotFound)
		mustErrIs(t, s.MFA().PutBrowser(ctx, &store.MFABrowser{TenantID: "a", UserID: "other", Hash: "x"}), store.ErrNotFound)
	})
	t.Run("MFAGuardianDefaults", func(t *testing.T) {
		s := setup(t)
		g, e := s.MFA().GetGuardian(ctx, "a")
		mustNoErr(t, e)
		if len(g.Factors) != 8 || len(g.Policies) != 0 {
			t.Fatalf("defaults: %+v", g)
		}
		for k, v := range g.Factors {
			if v {
				t.Errorf("%s enabled", k)
			}
		}
	})
	t.Run("MFAGuardianVersionConflict", func(t *testing.T) {
		s := setup(t)
		g, e := s.MFA().GetGuardian(ctx, "a")
		mustNoErr(t, e)
		g.Factors["otp"] = true
		mustNoErr(t, s.MFA().PutGuardian(ctx, g, 0))
		mustErrIs(t, s.MFA().PutGuardian(ctx, g, 0), store.ErrConflict)
		g.Factors["otp"] = false
		got, e := s.MFA().GetGuardian(ctx, "a")
		mustNoErr(t, e)
		if !got.Factors["otp"] || got.Version != 1 {
			t.Fatal(got)
		}
	})
	t.Run("MFAAuthenticatorCRUDTenantIsolation", func(t *testing.T) {
		s := setup(t)
		a := &store.Authenticator{TenantID: "a", UserID: "u", ID: "id", Type: "totp", SealedSecret: []byte("secret")}
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, a))
		a.SealedSecret[0] = 'x'
		g, e := s.MFA().GetAuthenticator(ctx, "a", "u", "id")
		mustNoErr(t, e)
		if string(g.SealedSecret) != "secret" {
			t.Fatal(g)
		}
		_, e = s.MFA().GetAuthenticator(ctx, "b", "u", "id")
		mustErrIs(t, e, store.ErrNotFound)
		_, e = s.MFA().GetAuthenticator(ctx, "a", "other", "id")
		mustErrIs(t, e, store.ErrNotFound)
		g.Name = "name"
		mustNoErr(t, s.MFA().UpdateAuthenticator(ctx, g))
		list, e := s.MFA().ListAuthenticators(ctx, "a", "u")
		mustNoErr(t, e)
		if len(list) != 1 || list[0].Name != "name" {
			t.Fatal(list)
		}
		mustNoErr(t, s.MFA().DeleteAuthenticator(ctx, "a", "u", "id"))
		_, e = s.MFA().GetAuthenticator(ctx, "a", "u", "id")
		mustErrIs(t, e, store.ErrNotFound)
	})
	t.Run("MFAWebAuthnCredentialUnique", func(t *testing.T) {
		s := setup(t)
		a := &store.Authenticator{TenantID: "a", UserID: "u", ID: "1", CredentialID: []byte("cred")}
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, a))
		a.ID = "2"
		mustErrIs(t, s.MFA().CreateAuthenticator(ctx, a), store.ErrConflict)
		a.TenantID = "b"
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, a))
	})
	t.Run("MFATOTPStepReplay", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "id", Type: "totp"}))
		errs := parallel(2, func(int) error { return s.MFA().AcceptTOTPStep(ctx, "a", "u", "id", 10, now) })
		oneSuccess(t, errs)
	})
	t.Run("MFARecoveryReplaceRace", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "id", Type: "recovery-code", CodeHash: "old"}))
		errs := parallel(2, func(int) error { return s.MFA().ReplaceRecoveryCode(ctx, "a", "u", "old", "new", now) })
		oneSuccess(t, errs)
	})
	t.Run("MFASignCountMonotonic", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: "u", ID: "id"}))
		mustNoErr(t, s.MFA().AcceptSignCount(ctx, "a", "u", "id", 0, now))
		mustNoErr(t, s.MFA().AcceptSignCount(ctx, "a", "u", "id", 3, now))
		mustErrIs(t, s.MFA().AcceptSignCount(ctx, "a", "u", "id", 3, now), store.ErrPrecondition)
	})
	t.Run("MFATokenConsumeOnce", func(t *testing.T) {
		s := setup(t)
		v := &store.MFAToken{TenantID: "a", Hash: "h", ClientID: "c", UserID: "u", ExpiresAt: now.Add(time.Minute)}
		mustNoErr(t, s.MFA().CreateMFAToken(ctx, v))
		_, e := s.MFA().ConsumeMFAToken(ctx, "a", "h", "other", now)
		mustErrIs(t, e, store.ErrNotFound)
		_, e = s.MFA().ConsumeMFAToken(ctx, "a", "h", "c", now)
		mustNoErr(t, e)
		_, e = s.MFA().ConsumeMFAToken(ctx, "a", "h", "c", now)
		mustErrIs(t, e, store.ErrNotFound)
		v.Hash = "expired"
		v.ExpiresAt = now
		mustNoErr(t, s.MFA().CreateMFAToken(ctx, v))
		_, e = s.MFA().ConsumeMFAToken(ctx, "a", "expired", "c", now)
		mustErrIs(t, e, store.ErrNotFound)
	})
	t.Run("MFAChallengeAttemptsAndExpiry", func(t *testing.T) {
		s := setup(t)
		v := &store.MFAChallenge{TenantID: "a", ID: "id", UserID: "u", ExpiresAt: now.Add(time.Minute)}
		mustNoErr(t, s.MFA().CreateChallenge(ctx, v))
		n, e := s.MFA().FailChallenge(ctx, "a", "id")
		mustNoErr(t, e)
		if n != 1 {
			t.Fatal(n)
		}
		_, e = s.MFA().GetChallenge(ctx, "a", "id", v.ExpiresAt)
		mustErrIs(t, e, store.ErrNotFound)
		mustErrIs(t, s.MFA().ConsumeChallenge(ctx, "a", "id", v.ExpiresAt), store.ErrPrecondition)
		mustNoErr(t, s.MFA().ConsumeChallenge(ctx, "a", "id", now))
		mustErrIs(t, s.MFA().ConsumeChallenge(ctx, "a", "id", now), store.ErrPrecondition)
	})
	t.Run("MFATicketSingleUse", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.MFA().CreateTicket(ctx, &store.EnrollmentTicket{TenantID: "a", Hash: "h", UserID: "u", ExpiresAt: now.Add(time.Minute)}))
		_, e := s.MFA().ConsumeTicket(ctx, "a", "h", now)
		mustNoErr(t, e)
		_, e = s.MFA().ConsumeTicket(ctx, "a", "h", now)
		mustErrIs(t, e, store.ErrNotFound)
	})
	t.Run("MFARememberEpoch", func(t *testing.T) {
		s := setup(t)
		u := newUser("a", "u", "u@example.com", "u")
		mustNoErr(t, s.Users().Create(ctx, u))
		mustNoErr(t, s.MFA().BumpRememberEpoch(ctx, "a", u.UserID))
		g, e := s.Users().Get(ctx, "a", u.UserID)
		mustNoErr(t, e)
		if g.RememberBrowserEpoch != 1 {
			t.Fatal(g.RememberBrowserEpoch)
		}
		mustErrIs(t, s.MFA().BumpRememberEpoch(ctx, "b", u.UserID), store.ErrNotFound)
	})
	t.Run("MFAPurge", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.MFA().PutBrowser(ctx, &store.MFABrowser{TenantID: "a", Hash: "h", UserID: "u", ExpiresAt: now.Add(-time.Second)}))
		n, e := s.MFA().PurgeMFA(ctx, now, 1)
		mustNoErr(t, e)
		if n != 1 {
			t.Fatal(n)
		}
		_, e = s.MFA().GetBrowser(ctx, "a", "h", now)
		mustErrIs(t, e, store.ErrNotFound)
	})
	t.Run("MFADeleteUserAndTenant", func(t *testing.T) {
		s := setup(t)
		u := newUser("a", "u", "u@example.com", "u")
		mustNoErr(t, s.Users().Create(ctx, u))
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: "a", UserID: u.UserID, ID: "id"}))
		mustNoErr(t, s.Users().Delete(ctx, "a", u.UserID))
		_, e := s.MFA().GetAuthenticator(ctx, "a", u.UserID, "id")
		mustErrIs(t, e, store.ErrNotFound)
		mustNoErr(t, s.MFA().PutBrowser(ctx, &store.MFABrowser{TenantID: "a", Hash: "h", UserID: "u", ExpiresAt: now.Add(time.Minute)}))
		mustNoErr(t, s.Tenants().Delete(ctx, "a"))
		_, e = s.MFA().GetBrowser(ctx, "a", "h", now)
		mustErrIs(t, e, store.ErrNotFound)
	})
	t.Run("SessionMarkMFA", func(t *testing.T) {
		s := setup(t)
		v := newSession("a", "id", "hash")
		mustNoErr(t, s.Sessions().Create(ctx, v))
		mustNoErr(t, s.Sessions().MarkMFA(ctx, "a", "id", now))
		g, e := s.Sessions().Get(ctx, "a", "id")
		mustNoErr(t, e)
		if !g.MFAAt.Equal(now) {
			t.Fatal(g.MFAAt)
		}
		mustErrIs(t, s.Sessions().MarkMFA(ctx, "b", "id", now), store.ErrNotFound)
	})
}
func oneSuccess(t *testing.T, errs []error) {
	t.Helper()
	n := 0
	for _, e := range errs {
		if e == nil {
			n++
		} else if !errors.Is(e, store.ErrPrecondition) {
			t.Fatal(e)
		}
	}
	if n != 1 {
		t.Fatalf("successes=%d errors=%v", n, errs)
	}
}
