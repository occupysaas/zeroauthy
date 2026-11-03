package oauth

import (
	"context"
	"testing"
	"time"
)

func (f *fixture) setMFAPolicy(t *testing.T, policies ...string) {
	t.Helper()
	ctx := context.Background()
	g, e := f.st.MFA().GetGuardian(ctx, f.tenantID(t, "acme"))
	if e != nil {
		t.Fatal(e)
	}
	g.Policies = append([]string{}, policies...)
	if e = f.st.MFA().PutGuardian(ctx, g, g.Version); e != nil {
		t.Fatal(e)
	}
}

// Review C1: a password alone must not mint an MFA API token for a user with
// an enrolled authenticator, even when no tenant policy requires MFA.
func TestMFAAPIAudienceRequiresMFAForEnrolledUser(t *testing.T) {
	f, _ := mfaFixture(t)
	tok := f.mfaRequired(t)
	s, _ := f.associateOTP(t, tok)
	f.proveOTP(t, tok, s)
	f.setMFAPolicy(t)
	mfaAud := "https://acme.example.test/mfa/"
	w, b := f.call(t, false, tokenCall{host: acmeHost, form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", mfaAud, "scope", "remove:authenticators read:authenticators")})
	if w.Code != 403 || b["error"] != "mfa_required" {
		t.Fatalf("password-only MFA API token=%d %v", w.Code, b)
	}
	next, _ := b["mfa_token"].(string)
	f.h.Now = func() time.Time { return fixedNow().Add(time.Minute) }
	b = f.proveOTP(t, next, s)
	if b["access_token"] == nil || b["scope"] != "read:authenticators remove:authenticators" && b["scope"] != "remove:authenticators read:authenticators" {
		t.Fatalf("MFA API token after OTP=%v", b)
	}
	// An ordinary audience without a policy still does not require MFA.
	w, b = f.call(t, false, tokenCall{host: acmeHost, form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid")})
	if w.Code != 200 {
		t.Fatalf("ordinary password grant=%d %v", w.Code, b)
	}
}

// A user without an enrolled authenticator may still obtain an enrollment
// token for the MFA API with only a password.
func TestMFAAPIAudienceUnenrolledUserPasswordOnly(t *testing.T) {
	f, _ := mfaFixture(t)
	f.setMFAPolicy(t)
	w, b := f.call(t, false, tokenCall{host: acmeHost, form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://acme.example.test/mfa/", "scope", "enroll")})
	if w.Code != 200 || b["scope"] != "enroll" {
		t.Fatalf("unenrolled MFA API token=%d %v", w.Code, b)
	}
}
