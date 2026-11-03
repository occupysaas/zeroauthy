package mfa

import (
	"errors"
	"testing"
	"time"
)

// Review I2: renewal keeps the pending method and its secret, so a code from
// the authenticator scanned before the five-minute expiry still confirms.
func TestRenewTOTPChallengeKeepsEnrollmentSecret(t *testing.T) {
	f := newServiceFixture(t)
	e, err := f.svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(6 * time.Minute)
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: codeAt(t, e.Secret, f.now)}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired challenge: %v", err)
	}
	c, err := f.svc.RenewTOTPChallenge(f.ctx, "tenant", "user", e.AuthenticatorID)
	if err != nil || c.ID == e.ChallengeID || c.AuthenticatorID != e.AuthenticatorID {
		t.Fatalf("renew: %+v %v", c, err)
	}
	e.ChallengeID = c.ID
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: codeAt(t, e.Secret, f.now)}); err != nil {
		t.Fatalf("confirm after renewal: %v", err)
	}
	if _, err = f.svc.RenewTOTPChallenge(f.ctx, "tenant", "other", e.AuthenticatorID); err == nil {
		t.Fatal("renewed another user's method")
	}
}
