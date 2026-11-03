package mfa

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
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

// Review M4: a colon in the issuer or account is percent-encoded so the
// label's single issuer separator stays unambiguous.
func TestTOTPURIEscapesLabelColons(t *testing.T) {
	got := TOTPURI("Acme: Prod", "user:1", "ABC234")
	if !strings.HasPrefix(got, "otpauth://totp/Acme%20%3A%20Prod:user%3A1?") && !strings.HasPrefix(got, "otpauth://totp/Acme%3A%20Prod:user%3A1?") {
		t.Fatal(got)
	}
	u, err := url.Parse(got)
	if err != nil || u.Query().Get("issuer") != "Acme: Prod" {
		t.Fatal(got, err)
	}
}

// Review M4: a username-only user gets a non-empty authenticator label.
func TestTOTPEnrollmentLabelFallsBack(t *testing.T) {
	f := newServiceFixture(t)
	for _, u := range []store.User{{TenantID: "tenant", UserID: "auth0|named", Username: "jdoe"}, {TenantID: "tenant", UserID: "auth0|bare"}} {
		if err := f.st.Users().Create(f.ctx, &u); err != nil {
			t.Fatal(err)
		}
	}
	for uid, want := range map[string]string{"auth0|named": "jdoe", "auth0|bare": "auth0|bare", "user": "one@example.test"} {
		e, err := f.svc.BeginEnroll(f.ctx, "tenant", uid, "otp", "")
		if err != nil {
			t.Fatal(err)
		}
		for _, uri := range []string{e.URI, mustDisplay(t, f, uid, e.AuthenticatorID)} {
			u, err := url.Parse(uri)
			if err != nil || u.Path != "/tenant:"+want {
				t.Fatalf("%s label %q (%v)", uid, uri, err)
			}
		}
	}
}
func mustDisplay(t *testing.T, f *serviceFixture, uid, id string) string {
	t.Helper()
	d, err := f.svc.EnrollmentDisplay(f.ctx, "tenant", uid, id)
	if err != nil {
		t.Fatal(err)
	}
	return d.URI
}

// Review M5: imported or Management API secrets in lower case, with spaces
// or with base32 padding are normalized before strict decoding.
func TestNormalizeTOTPSecret(t *testing.T) {
	const canonical = "JBSWY3DPEHPK3PXP"
	for _, in := range []string{canonical, "jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "JBSWY3DPEHPK3PXP====", "jbswy3dpehpk3pxp"} {
		if got := NormalizeTOTPSecret(in); got != canonical {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if got := NormalizeTOTPSecret("JBSWY3DP-EHPK3PXP"); got != "JBSWY3DP-EHPK3PXP" {
		t.Errorf("hyphen must stay invalid -> %q", got)
	}
	if got := NormalizeTOTPSecret("MZXW6==="); got != "MZXW6" {
		t.Errorf("padding -> %q", got)
	}
	w := f0(t)
	sealed, err := SealTOTPSecret(w, "t", "u", "totp|dev_x", "jbsw y3dp ehpk 3pxp")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := w.Unwrap(sealed, totpAAD("t", "u", "totp|dev_x"))
	if err != nil || string(plain) != canonical {
		t.Fatalf("sealed %q %v", plain, err)
	}
}
func f0(t *testing.T) keys.Wrapper {
	t.Helper()
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}
