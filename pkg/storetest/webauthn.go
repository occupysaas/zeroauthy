package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testWebAuthn runs the Plan 33b WebAuthn storage contract.
func testWebAuthn(t *testing.T, factory Factory) {
	ctx := context.Background()
	now := ts(0)
	setup := func(t *testing.T) store.Store {
		s := open(t, factory)
		for _, name := range []string{"a", "b"} {
			mustNoErr(t, s.Tenants().Create(ctx, newTenant(name)))
			mustNoErr(t, s.Users().Create(ctx, newUser("ten_"+name, "u1", "u1@"+name+".test", "")))
			mustNoErr(t, s.Users().Create(ctx, newUser("ten_"+name, "u2", "u2@"+name+".test", "")))
		}
		return s
	}
	n := 0
	passkey := func(tid, uid string) *store.Authenticator {
		n++
		return &store.Authenticator{
			TenantID: tid, UserID: uid, ID: fmt.Sprintf("passkey|dev_%020d", n), Type: "passkey", Name: "Passkey",
			Confirmed: true, CredentialID: []byte(fmt.Sprintf("cred-%d", n)), PublicKey: []byte{0xa1, 0x01, 0x02},
			RPID: "a.example.test", PublicData: json.RawMessage(`{"identity_user_id":"u1","backup_eligible":true}`), CreatedAt: now,
		}
	}

	t.Run("CreatePasskeyLimit", func(t *testing.T) {
		s := setup(t)
		for range 20 {
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("ten_a", "auth0|u1"), 20))
		}
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, passkey("ten_a", "auth0|u1"), 20), store.ErrPrecondition)
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("ten_a", "auth0|u2"), 20))
	})
	t.Run("CreatePasskeyLimitConcurrent", func(t *testing.T) {
		s := setup(t)
		for range 19 {
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, passkey("ten_a", "auth0|u1"), 20))
		}
		keys := make([]*store.Authenticator, 10)
		for i := range keys {
			keys[i] = passkey("ten_a", "auth0|u1")
		}
		done := make(chan []error, 1)
		go func() { done <- parallel(10, func(i int) error { return s.WebAuthn().CreatePasskey(ctx, keys[i], 20) }) }()
		select {
		case errs := <-done:
			ok := 0
			for _, err := range errs {
				if err == nil {
					ok++
				} else if !errors.Is(err, store.ErrPrecondition) {
					t.Fatalf("unexpected error %v", err)
				}
			}
			mustEqual(t, ok, 1)
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent creates did not return")
		}
	})
	t.Run("CredentialUniquePerTenant", func(t *testing.T) {
		s := setup(t)
		a := passkey("ten_a", "auth0|u1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		dup := passkey("ten_a", "auth0|u2")
		dup.CredentialID = a.CredentialID
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, dup, 20), store.ErrConflict)
		roaming := passkey("ten_a", "auth0|u2")
		roaming.Type, roaming.ID, roaming.CredentialID = "webauthn-roaming", "webauthn-roaming|dev_roaming0000000001", a.CredentialID
		mustErrIs(t, s.MFA().CreateAuthenticator(ctx, roaming), store.ErrConflict)
		other := passkey("ten_b", "auth0|u1")
		other.CredentialID = a.CredentialID
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, other, 20))
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", a.CredentialID)
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "auth0|u1")
	})
	t.Run("CreateUserWithPasskeyAtomic", func(t *testing.T) {
		s := setup(t)
		existing := passkey("ten_a", "auth0|u1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, existing, 20))
		u := newUser("ten_a", "u3", "u3@a.test", "")
		u.Identities[0].PasswordHash = ""
		a := passkey("ten_a", "auth0|u3")
		a.CredentialID = existing.CredentialID
		mustErrIs(t, s.WebAuthn().CreateUserWithPasskey(ctx, u, a), store.ErrConflict)
		_, err := s.Users().Get(ctx, "ten_a", "auth0|u3")
		mustErrIs(t, err, store.ErrNotFound)
		a.CredentialID = []byte("fresh")
		mustNoErr(t, s.WebAuthn().CreateUserWithPasskey(ctx, u, a))
		got, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", []byte("fresh"))
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "auth0|u3")
	})
	t.Run("AcceptAssertionCounter", func(t *testing.T) {
		for _, c := range []struct {
			stored, got uint32
			ok          bool
		}{{0, 0, true}, {0, 5, true}, {5, 5, false}, {5, 4, false}, {5, 0, false}, {5, 6, true}} {
			s := setup(t)
			a := passkey("ten_a", "auth0|u1")
			a.SignCount = c.stored
			mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
			err := s.WebAuthn().AcceptAssertion(ctx, "ten_a", "auth0|u1", a.ID, c.got, false, now)
			if c.ok {
				mustNoErr(t, err)
			} else {
				mustErrIs(t, err, store.ErrPrecondition)
			}
		}
		s := setup(t)
		a := passkey("ten_a", "auth0|u1")
		a.SignCount = 6
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		ok := 0
		for _, err := range parallel(2, func(int) error {
			return s.WebAuthn().AcceptAssertion(ctx, "ten_a", "auth0|u1", a.ID, 7, false, now)
		}) {
			if err == nil {
				ok++
			}
		}
		mustEqual(t, ok, 1)
	})
	t.Run("AcceptAssertionWritesBackupStateAndLastAuth", func(t *testing.T) {
		s := setup(t)
		a := passkey("ten_a", "auth0|u1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		mustNoErr(t, s.WebAuthn().AcceptAssertion(ctx, "ten_a", "auth0|u1", a.ID, 0, true, ts(time.Hour)))
		got, err := s.MFA().GetAuthenticator(ctx, "ten_a", "auth0|u1", a.ID)
		mustNoErr(t, err)
		mustEqual(t, got.LastAuthAt.Equal(ts(time.Hour)), true)
		var pub map[string]any
		mustNoErr(t, json.Unmarshal(got.PublicData, &pub))
		mustEqual(t, pub["backed_up"], true)
		mustEqual(t, pub["identity_user_id"], "u1")
	})
	t.Run("MovePasskeysAllAndByIdentity", func(t *testing.T) {
		s := setup(t)
		a1, a2 := passkey("ten_a", "auth0|u1"), passkey("ten_a", "auth0|u1")
		a2.PublicData = json.RawMessage(`{"identity_user_id":"other"}`)
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a1, 20))
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a2, 20))
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "ten_a", "auth0|u1", "auth0|u2", "other"))
		g2, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", a2.CredentialID)
		mustNoErr(t, err)
		mustEqual(t, g2.UserID, "auth0|u2")
		g1, _ := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", a1.CredentialID)
		mustEqual(t, g1.UserID, "auth0|u1")
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "ten_a", "auth0|u1", "auth0|u2", ""))
		g1, _ = s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", a1.CredentialID)
		mustEqual(t, g1.UserID, "auth0|u2")
	})
	t.Run("DeleteUserAuthenticatorsNilKeepsPasskeys", func(t *testing.T) {
		s := setup(t)
		a := passkey("ten_a", "auth0|u1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		otp := &store.Authenticator{TenantID: "ten_a", UserID: "auth0|u1", ID: "totp|dev_00000000000000000001", Type: "totp", Confirmed: true, SealedSecret: []byte("s"), CreatedAt: now}
		mustNoErr(t, s.MFA().CreateAuthenticator(ctx, otp))
		mustNoErr(t, s.MFA().DeleteUserAuthenticators(ctx, "ten_a", "auth0|u1", nil))
		list, err := s.MFA().ListAuthenticators(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, len(list), 1)
		mustEqual(t, list[0].Type, "passkey")
	})
	t.Run("DeleteUserMFARemovesPasskeys", func(t *testing.T) {
		s := setup(t)
		a := passkey("ten_a", "auth0|u1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		mustNoErr(t, s.MFA().DeleteUserMFA(ctx, "ten_a", "auth0|u1"))
		_, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", a.CredentialID)
		mustErrIs(t, err, store.ErrNotFound)
	})
	t.Run("SnoozeUpsertAndExpiry", func(t *testing.T) {
		s := setup(t)
		sn := &store.WebAuthnSnooze{TenantID: "ten_a", UserID: "auth0|u1", Kind: "passkey-progressive", ScopeKey: "a.example.test", Until: ts(time.Hour)}
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, sn))
		sn2 := *sn
		sn2.Until = ts(2 * time.Hour)
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, &sn2))
		got, err := s.WebAuthn().GetSnooze(ctx, "ten_a", "auth0|u1", "passkey-progressive", "a.example.test", ts(90*time.Minute))
		mustNoErr(t, err)
		mustEqual(t, got.Until.Equal(ts(2*time.Hour)), true)
		_, err = s.WebAuthn().GetSnooze(ctx, "ten_a", "auth0|u1", "passkey-progressive", "a.example.test", ts(3*time.Hour))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.WebAuthn().GetSnooze(ctx, "ten_b", "auth0|u1", "passkey-progressive", "a.example.test", now)
		mustErrIs(t, err, store.ErrNotFound)
	})
	t.Run("HostTenantsUnder", func(t *testing.T) {
		s := setup(t)
		for _, h := range []store.HostBinding{
			{Host: "example.com", TenantID: "ten_a", Kind: store.HostOperator, Active: true},
			{Host: "login.example.com", TenantID: "ten_b", Kind: store.HostOperator, Active: true},
			{Host: "ample.com", TenantID: "ten_b", Kind: store.HostOperator, Active: true},
		} {
			h := h
			mustNoErr(t, s.CustomDomains().PutHost(ctx, &h))
		}
		got, err := s.WebAuthn().HostTenantsUnder(ctx, "example.com", 10)
		mustNoErr(t, err)
		slices.Sort(got)
		mustEqual(t, got, []string{"ten_a", "ten_b"})
		got, _ = s.WebAuthn().HostTenantsUnder(ctx, "mple.com", 10)
		mustEqual(t, len(got), 0)
	})
	t.Run("SessionAuthMethodsRoundTrip", func(t *testing.T) {
		s := setup(t)
		sess := newSession("ten_a", "s1", "hash-s1")
		mustNoErr(t, s.Sessions().Create(ctx, sess))
		got, err := s.Sessions().Get(ctx, "ten_a", "s1")
		mustNoErr(t, err)
		mustEqual(t, got.AuthMethods == nil, true)
		sess2 := newSession("ten_a", "s2", "hash-s2")
		sess2.AuthMethods = []store.AuthMethod{{Name: "passkey", At: now}, {Name: "mfa", Type: "otp", At: now}}
		mustNoErr(t, s.Sessions().Create(ctx, sess2))
		got, err = s.Sessions().Get(ctx, "ten_a", "s2")
		mustNoErr(t, err)
		mustEqual(t, len(got.AuthMethods), 2)
		mustEqual(t, got.AuthMethods[1].Type, "otp")
	})
	t.Run("ClientMobileRoundTrip", func(t *testing.T) {
		s := setup(t)
		c := newClient("ten_a", "mobile")
		c.Mobile = &store.ClientMobile{IOS: &store.ClientMobileIOS{TeamID: "T1", AppBundleIdentifier: "com.example.app"},
			Android: &store.ClientMobileAndroid{AppPackageName: "com.example.app", SHA256CertFingerprints: []string{"AA:BB"}}}
		mustNoErr(t, s.Clients().Create(ctx, c))
		got, err := s.Clients().Get(ctx, "ten_a", "mobile")
		mustNoErr(t, err)
		mustEqual(t, got.Mobile.IOS.TeamID, "T1")
		mustEqual(t, got.Mobile.Android.SHA256CertFingerprints, []string{"AA:BB"})
	})
	t.Run("TenantDomainRPIDsRoundTrip", func(t *testing.T) {
		s := open(t, factory)
		tn := newTenant("rp")
		tn.DomainRPIDs = map[string]string{"login.rp.test": "rp.test"}
		mustNoErr(t, s.Tenants().Create(ctx, tn))
		got, err := s.Tenants().Get(ctx, tn.ID)
		mustNoErr(t, err)
		mustEqual(t, got.DomainRPIDs["login.rp.test"], "rp.test")
	})
	t.Run("ChallengeBindingRoundTrip", func(t *testing.T) {
		s := setup(t)
		c := &store.MFAChallenge{TenantID: "ten_a", ID: "ch1", Kind: "webauthn", Challenge: []byte("raw"), Binding: []byte(`{"purpose":"passkey-login"}`), ExpiresAt: ts(time.Minute)}
		mustNoErr(t, s.MFA().CreateChallenge(ctx, c))
		got, err := s.MFA().GetChallenge(ctx, "ten_a", "ch1", now)
		mustNoErr(t, err)
		mustEqual(t, string(got.Binding), `{"purpose":"passkey-login"}`)
	})
	t.Run("PurgeWebAuthnExpired", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "ten_a", UserID: "auth0|u1", Kind: "passkey-local", ScopeKey: "x", Until: ts(time.Minute)}))
		mustNoErr(t, s.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: "ten_a", UserID: "auth0|u1", Kind: "passkey-local", ScopeKey: "y", Until: ts(time.Hour)}))
		got, err := s.WebAuthn().PurgeWebAuthn(ctx, ts(30*time.Minute), 100)
		mustNoErr(t, err)
		mustEqual(t, got, 1)
		_, err = s.WebAuthn().GetSnooze(ctx, "ten_a", "auth0|u1", "passkey-local", "y", now)
		mustNoErr(t, err)
	})
	t.Run("TenantIsolation", func(t *testing.T) {
		s := setup(t)
		a := passkey("ten_a", "auth0|u1")
		mustNoErr(t, s.WebAuthn().CreatePasskey(ctx, a, 20))
		_, err := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_b", a.CredentialID)
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.WebAuthn().AcceptAssertion(ctx, "ten_b", "auth0|u1", a.ID, 1, false, now), store.ErrNotFound)
		mustNoErr(t, s.WebAuthn().MovePasskeys(ctx, "ten_b", "auth0|u1", "auth0|u2", ""))
		g, _ := s.WebAuthn().GetAuthenticatorByCredentialID(ctx, "ten_a", a.CredentialID)
		mustEqual(t, g.UserID, "auth0|u1")
		foreign := passkey("ten_b", "auth0|missing")
		mustErrIs(t, s.WebAuthn().CreatePasskey(ctx, foreign, 20), store.ErrNotFound)
	})
}
