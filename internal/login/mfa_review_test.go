package login

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Review I2: a user who keeps the TOTP enrollment page open past the
// five-minute challenge lifetime can still confirm with the scanned secret.
func TestMFAOTPEnrollmentAfterChallengeExpiry(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	f.begin(t)
	p := f.page(t, "/u/mfa-otp-enrollment")
	m := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String())
	if m == nil {
		t.Fatalf("missing secret %s", p.Body)
	}
	*f.clock = f.clock.Add(6 * time.Minute)
	p = f.page(t, "/u/mfa-otp-enrollment")
	if again := regexp.MustCompile(`<code id="mfa-secret">([A-Z2-7]+)</code>`).FindStringSubmatch(p.Body.String()); again == nil || again[1] != m[1] {
		t.Fatal("reload changed the scanned secret")
	}
	r := f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(m[1], *f.clock)}})
	if r.Code != 200 || !regexp.MustCompile(`<code id="recovery-code">([A-Z0-9]{24})</code>`).MatchString(r.Body.String()) {
		t.Fatalf("enrollment after expiry %d %s", r.Code, r.Body)
	}
}

// Review I2: an enrolled user who waits on the OTP challenge page past the
// challenge lifetime can still verify.
func TestMFAOTPChallengeAfterChallengeExpiry(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", false)
	f.begin(t)
	f.page(t, "/u/mfa-otp-challenge")
	*f.clock = f.clock.Add(6 * time.Minute)
	r := f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	if !strings.Contains(r.Header().Get("Location"), "code=") {
		t.Fatalf("challenge after expiry %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
}

// Review I2: an expired email code keeps the resend action available, and the
// resent code completes the challenge.
func TestMFAEmailExpiredCodeOffersResend(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "email")
	f.enrolled(t, "email", false)
	f.begin(t)
	f.page(t, "/u/mfa-email-challenge")
	code := f.mail.codes[len(f.mail.codes)-1]
	*f.clock = f.clock.Add(6 * time.Minute)
	r := f.post(t, "/u/mfa-email-challenge", url.Values{"code": {code}})
	if r.Code != 400 || !strings.Contains(r.Body.String(), `value="resend"`) {
		t.Fatalf("expired email %d %s", r.Code, r.Body)
	}
	if m := csrfField.FindStringSubmatch(r.Body.String()); m != nil {
		f.csrf = m[1]
	}
	r = f.post(t, "/u/mfa-email-challenge", url.Values{"action": {"resend"}})
	if r.Code != 200 {
		t.Fatalf("resend %d %s", r.Code, r.Body)
	}
	if m := csrfField.FindStringSubmatch(r.Body.String()); m != nil {
		f.csrf = m[1]
	}
	r = f.post(t, "/u/mfa-email-challenge", url.Values{"code": {f.mail.codes[len(f.mail.codes)-1]}})
	if !strings.Contains(r.Header().Get("Location"), "code=") {
		t.Fatalf("resent code %d %s %s", r.Code, r.Header().Get("Location"), r.Body)
	}
}
