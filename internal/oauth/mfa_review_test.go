package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
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

func (f *fixture) setMFAFactors(t *testing.T, factors map[string]bool) {
	t.Helper()
	ctx := context.Background()
	g, e := f.st.MFA().GetGuardian(ctx, f.tenantID(t, "acme"))
	if e != nil {
		t.Fatal(e)
	}
	g.Factors = factors
	if e = f.st.MFA().PutGuardian(ctx, g, g.Version); e != nil {
		t.Fatal(e)
	}
}

// Review I3: an email method whose address no longer matches the verified
// user email is not a usable factor; the user must be routed to enrollment
// and that enrollment must complete.
func TestMFAStaleEmailMethodRoutesToEnrollment(t *testing.T) {
	f, _ := mfaFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID(t, "acme"), f.aliceID(t)
	if e := f.st.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: tid, UserID: uid, ID: "email|dev_stale", Type: "email", Email: "old@acme.test", Confirmed: true, CreatedAt: fixedNow()}); e != nil {
		t.Fatal(e)
	}
	tok := f.mfaRequired(t)
	s, _ := f.associateOTP(t, tok)
	f.proveOTP(t, tok, s)
}

// Review I4: a password-grant user whose only factor was disabled can enroll
// and confirm a replacement factor.
func TestMFADisabledFactorReplacementEnrollment(t *testing.T) {
	f, mail := mfaFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID(t, "acme"), f.aliceID(t)
	if e := f.st.MFA().CreateAuthenticator(ctx, &store.Authenticator{TenantID: tid, UserID: uid, ID: "totp|dev_old", Type: "totp", Confirmed: true, LastStep: -1, CreatedAt: fixedNow()}); e != nil {
		t.Fatal(e)
	}
	f.setMFAFactors(t, map[string]bool{"email": true, "recovery-code": true})
	tok := f.mfaRequired(t)
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["oob"],"oob_channels":["email"],"email":"alice@acme.test"}`)
	if w.Code != 200 {
		t.Fatalf("email associate=%d %v", w.Code, b)
	}
	form := mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", mail.code)
	w, b = f.call(t, false, tokenCall{host: acmeHost, form: form})
	if w.Code != 200 {
		t.Fatalf("replacement OOB=%d %v", w.Code, b)
	}
}

// Review M2: /mfa/associate displays the first recovery code but persists it
// only when the OTP enrollment is confirmed; the displayed code then works.
func TestMFAAssociateRecoveryPersistedOnConfirm(t *testing.T) {
	f, _ := mfaFixture(t)
	ctx := context.Background()
	tid, uid := f.tenantID(t, "acme"), f.aliceID(t)
	tok := f.mfaRequired(t)
	s, code := f.associateOTP(t, tok)
	list, _ := f.st.MFA().ListAuthenticators(ctx, tid, uid)
	for _, a := range list {
		if a.Type == "recovery-code" {
			t.Fatal("recovery code persisted before OTP confirmation")
		}
	}
	b := f.proveOTP(t, tok, s)
	if b["recovery_code"] != nil {
		t.Fatalf("second recovery code issued: %v", b)
	}
	tok = f.mfaRequired(t)
	w, b := f.call(t, false, tokenCall{host: acmeHost, form: mfaForm(recoveryGrant, tok, "recovery_code", code)})
	if w.Code != 200 {
		t.Fatalf("displayed recovery code rejected: %d %v", w.Code, b)
	}
}
