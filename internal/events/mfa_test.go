package events_test

import (
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"
)

func TestUserUpdatedOnEnroll(t *testing.T) {
	ctx, s := fixture(t)
	s.Users().Create(ctx, user("mfa"))
	a := &store.Authenticator{TenantID: "ten", UserID: "mfa", ID: "email|dev_12345678901234567890", Type: "email"}
	if err := s.MFA().CreateAuthenticator(ctx, a); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 1 {
		t.Fatal("unconfirmed emitted")
	}
	a.Confirmed = true
	if err := s.MFA().UpdateAuthenticator(ctx, a); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 2 {
		t.Fatal("confirmation did not emit user.updated")
	}
	if err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.MFA().DeleteAuthenticator(ctx, "ten", "mfa", a.ID); err != nil {
			return err
		}
		return tx.MFA().CreateAuthenticator(ctx, a)
	}); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 2 {
		t.Fatal("net unchanged multifactor emitted")
	}
	if err := s.MFA().DeleteAuthenticator(ctx, "ten", "mfa", a.ID); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 3 {
		t.Fatal("last removal did not emit")
	}
}
func TestUserUpdatedOnEnrollNestedRollbackAndProofUpdates(t *testing.T) {
	ctx, s := fixture(t)
	if err := s.Users().Create(ctx, user("mfa")); err != nil {
		t.Fatal(err)
	}
	a := &store.Authenticator{TenantID: "ten", UserID: "mfa", ID: "totp|dev_12345678901234567890", Type: "totp", Confirmed: true, LastStep: -1}
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.MFA().CreateAuthenticator(ctx, a); err != nil {
			return err
		}
		if err := tx.WithTx(ctx, func(nested store.Store) error {
			if err := nested.MFA().DeleteAuthenticator(ctx, "ten", "mfa", a.ID); err != nil {
				return err
			}
			return store.ErrInvalid
		}); err != store.ErrInvalid {
			t.Fatal(err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	events := all(t, ctx, s)
	if len(events) != 2 {
		t.Fatal("nested rollback lost or duplicated update", len(events))
	}
	var payload map[string]any
	if err = json.Unmarshal(events[1].Body, &payload); err != nil {
		t.Fatal(err)
	}
	data := payload["data"].(map[string]any)
	if len(data["object"].(map[string]any)["multifactor"].([]any)) != 1 || len(data["previous_object"].(map[string]any)["multifactor"].([]any)) != 0 {
		t.Fatal(payload)
	}
	if err = s.MFA().AcceptTOTPStep(ctx, "ten", "mfa", a.ID, 10, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = s.MFA().AcceptSignCount(ctx, "ten", "mfa", a.ID, 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = s.MFA().ReplaceRecoveryCode(ctx, "ten", "mfa", "", "hashed", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = s.MFA().BumpRememberEpoch(ctx, "ten", "mfa"); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 2 {
		t.Fatal("proof/recovery/remember mutation emitted user.updated")
	}
}
