package mfa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

func roamingFixture(t *testing.T) (*serviceFixture, *Service, rpid.Result) {
	t.Helper()
	f := newServiceFixture(t)
	g, _ := f.st.MFA().GetGuardian(f.ctx, "tenant")
	g.Factors["webauthn-roaming"] = true
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	if err := f.st.MFA().PutGuardian(f.ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	svc := f.svc.WithWebAuthnBinding(passkey.Binding{TxnID: "transaction", CookieHash: "browser", ClientID: "client", Realm: "db", RPID: "example.test", Origins: []string{"https://example.test"}})
	return f, svc, rpid.Result{Valid: true, RPID: "example.test", Origin: "https://example.test"}
}
func TestDecideWebAuthnFilters(t *testing.T) {
	g := &store.GuardianSettings{Factors: map[string]bool{"webauthn-roaming": true}, Policies: []string{"all-applications"}}
	in := DecideInput{Settings: g, Authenticators: []store.Authenticator{{Type: "webauthn-roaming", RPID: "foreign.test", Confirmed: true, CredentialID: []byte{1}, PublicKey: []byte{1}}}, WebAuthn: WebAuthnCapabilities{Available: true, RPID: "example.test"}}
	r, err := Decide(in)
	if err != nil || !r.Enroll || len(r.Factors) != 1 {
		t.Fatalf("foreign RP: %+v %v", r, err)
	}
	in.Authenticators[0].RPID = "example.test"
	r, err = Decide(in)
	if err != nil || r.Enroll {
		t.Fatalf("own RP %+v %v", r, err)
	}
	in.WebAuthn.Available = false
	if _, err = Decide(in); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("absent capability: %v", err)
	}
}
func TestRoamingEnrollAndChallenge(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Attachment != "cross-platform" || o.ResidentKey != "discouraged" || o.UserVerification != "discouraged" {
		t.Fatalf("options %+v", o)
	}
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform", OmitUserHandle: true})
	raw := key.Create(o, rp.Origin)
	if err = svc.StageWebAuthnEnroll(f.ctx, "tenant", "user", e, raw, "browser"); err != nil {
		t.Fatal(err)
	}
	// A second instance completes the verified registration, with no raw credential.
	replica := NewService(f.st, f.w, f.email, nil, nil, func() time.Time { return f.now }).WithWebAuthnBinding(passkey.Binding{TxnID: "transaction", CookieHash: "browser", ClientID: "client", Realm: "db", RPID: "example.test", Origins: []string{"https://example.test"}})
	for _, name := range []string{"", strings.Repeat("a", 21)} {
		if _, err = replica.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, name, "browser"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("nickname %q: %v", name, err)
		}
	}
	confirmed, err := replica.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "My key", "browser")
	if err != nil || confirmed.RecoveryCode == "" {
		t.Fatalf("confirmation %+v %v", confirmed, err)
	}
	if _, err = replica.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "My key", "browser"); err == nil {
		t.Fatal("replayed enrollment")
	}
	c, opts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
	if err != nil || len(opts.Allow) != 1 {
		t.Fatalf("challenge %+v %v", opts, err)
	}
	assertion := key.Get(opts, rp.Origin)
	if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, assertion); err != nil {
		t.Fatal(err)
	}
	if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, assertion); err == nil {
		t.Fatal("replayed assertion")
	}
}
func TestRoamingUVRequired(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	g, _ := f.st.MFA().GetGuardian(f.ctx, "tenant")
	g.Stored["webauthn-roaming/settings"] = []byte(`{"user_verification":"required"}`)
	_ = f.st.MFA().PutGuardian(f.ctx, g, g.Version)
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{})
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "browser"); err == nil {
		t.Fatal("UV-less registration accepted")
	}
	e, o, err = svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key = webauthntest.New(webauthntest.Options{UV: true})
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "browser"); err != nil {
		t.Fatal(err)
	}
	key.Opts.UV = false
	c, opts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, key.Get(opts, rp.Origin)); err == nil {
		t.Fatal("UV-less assertion accepted")
	}
	if f.events.count("gd_webauthn_challenge_failed") != 1 || f.events.count("gd_auth_failed") != 1 {
		t.Fatalf("missing failure events %+v", f.events.events)
	}
}
func TestWebAuthnThrottle(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	e, o, _ := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	key := webauthntest.New(webauthntest.Options{})
	if _, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "browser"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		c, _, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
		if err != nil {
			t.Fatal(err)
		}
		err = svc.VerifyWebAuthn(context.Background(), "tenant", "user", c, []byte(`{}`))
		if i == 10 && !errors.Is(err, ErrThrottled) {
			t.Fatalf("11th: %v", err)
		}
		if i < 10 && err == nil {
			t.Fatal("invalid accepted")
		}
	}
	f.now = f.now.Add(16 * time.Minute)
	c, _, _ := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
	if err := svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, []byte(`{}`)); errors.Is(err, ErrThrottled) {
		t.Fatal("window did not expire")
	}
}

func TestWebAuthnBindingAndFailedVerificationConsumes(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	if _, _, err := f.svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{}); err == nil {
		t.Fatal("missing trusted binding accepted")
	}
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{})
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "ua"); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"transaction", "browser", "origin", "user", "client", "purpose", "invalid-proof"} {
		t.Run(field, func(t *testing.T) {
			c, opts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
			if err != nil {
				t.Fatal(err)
			}
			b := svc.webAuthnBinding
			uid := "user"
			switch field {
			case "transaction":
				b.TxnID = "elsewhere"
			case "browser":
				b.CookieHash = "elsewhere"
			case "origin":
				b.Origins = []string{"https://other.example.test"}
			case "client":
				b.ClientID = "other"
			case "user":
				uid = "other"
			}
			raw := key.Get(opts, rp.Origin)
			var proofErr error
			if field == "purpose" {
				proofErr = svc.StageWebAuthnEnroll(f.ctx, "tenant", uid, &Enrollment{ChallengeID: c.ID}, raw, "ua")
			} else {
				if field == "invalid-proof" {
					raw = []byte(`{}`)
				}
				proofErr = svc.WithWebAuthnBinding(b).VerifyWebAuthn(f.ctx, "tenant", uid, c, raw)
			}
			if proofErr == nil {
				t.Fatal("wrong binding/proof accepted")
			}
			if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, key.Get(opts, rp.Origin)); err == nil {
				t.Fatal("failed verification did not consume challenge")
			}
		})
	}
}
func TestWebAuthnProofCommitRollbackAndEvents(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	tn, _ := f.st.Tenants().Get(f.ctx, "tenant")
	tn.CanonicalHost = "example.test"
	if err := f.st.Tenants().Update(f.ctx, tn); err != nil {
		t.Fatal(err)
	}
	wrapped := events.Wrap(f.st, events.Config{})
	svc = svc.WithStore(wrapped)
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{})
	if err = svc.StageWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "ua"); err != nil {
		t.Fatal(err)
	}
	aborted := errors.New("ticket already spent")
	if _, err = svc.WithProofCommit(func(store.Store) error { return aborted }).ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "Key", "ua"); !errors.Is(err, aborted) {
		t.Fatal(err)
	}
	list, _ := f.st.MFA().ListAuthenticators(f.ctx, "tenant", "user")
	if len(list) != 0 {
		t.Fatalf("rollback persisted methods %+v", list)
	}
	ev, err := wrapped.Events().EventsAfter(f.ctx, "tenant", 0, nil, 100, f.now.Add(time.Hour))
	if err != nil || len(ev) != 0 {
		t.Fatalf("rollback events %+v %v", ev, err)
	}
	confirmed, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "Key", "ua")
	if err != nil || confirmed.RecoveryCode == "" {
		t.Fatalf("retry %+v %v", confirmed, err)
	}
	ev, err = wrapped.Events().EventsAfter(f.ctx, "tenant", 0, nil, 100, f.now.Add(time.Hour))
	if err != nil || len(ev) != 1 || ev[0].Type != "user.updated" {
		t.Fatalf("commit events %+v %v", ev, err)
	}
	var payload map[string]any
	if err = json.Unmarshal(ev[0].Body, &payload); err != nil {
		t.Fatal(err)
	}
	serialized := string(ev[0].Body)
	if strings.Contains(serialized, "public_key") || strings.Contains(serialized, "user_handle") {
		t.Fatalf("credential metadata leaked: %s", serialized)
	}
	if f.events.count("gd_enrollment_complete") != 1 {
		t.Fatal("failed commit emitted success log")
	}
}
func TestWebAuthnFirstEnrollmentRPAndRace(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	// The old domain's confirmed key cannot block enrolling on this domain.
	old := &store.Authenticator{TenantID: "tenant", UserID: "user", ID: NewMethodID("webauthn-roaming"), Type: "webauthn-roaming", Confirmed: true, RPID: "foreign.test", CredentialID: []byte{1}, PublicKey: []byte{1}}
	if err := f.st.MFA().CreateAuthenticator(f.ctx, old); err != nil {
		t.Fatal(err)
	}
	svc = svc.WithFirstWebAuthnEnrollment()
	var enrollments []*Enrollment
	for i := 0; i < 2; i++ {
		e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
		if err != nil {
			t.Fatal(err)
		}
		key := webauthntest.New(webauthntest.Options{})
		if err = svc.StageWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "ua"); err != nil {
			t.Fatal(err)
		}
		enrollments = append(enrollments, e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, e := range enrollments {
		go func(e *Enrollment) {
			<-start
			_, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "Key", "ua")
			results <- err
		}(e)
	}
	close(start)
	winners := 0
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err == nil {
				winners++
			} else if !errors.Is(err, ErrAlreadyEnrolled) {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("confirmation blocked")
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
}
func TestWebAuthnStagedExpiryAndUVTightening(t *testing.T) {
	for _, tighten := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "UV-tightened"}[tighten], func(t *testing.T) {
			f, svc, rp := roamingFixture(t)
			e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
			if err != nil {
				t.Fatal(err)
			}
			key := webauthntest.New(webauthntest.Options{})
			if err = svc.StageWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "ua"); err != nil {
				t.Fatal(err)
			}
			if tighten {
				g, _ := f.st.MFA().GetGuardian(f.ctx, "tenant")
				g.Stored["webauthn-roaming/settings"] = []byte(`{"user_verification":"required"}`)
				if err = f.st.MFA().PutGuardian(f.ctx, g, g.Version); err != nil {
					t.Fatal(err)
				}
			} else {
				f.now = f.now.Add(6 * time.Minute)
			}
			if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "Key", "ua"); err == nil {
				t.Fatal("staged proof accepted after expiry/UV tightening")
			}
			list, _ := f.st.MFA().ListAuthenticators(f.ctx, "tenant", "user")
			if len(list) != 0 {
				t.Fatal("invalid confirmation persisted credential")
			}
		})
	}
}
func TestDecideWebAuthnProvidersAndRemember(t *testing.T) {
	for _, provider := range []string{"any", "guardian"} {
		in := DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"webauthn-roaming": true}}, Effects: &actionresult.MFAEffects{Provider: provider, AllowRememberBrowser: true}, WebAuthn: WebAuthnCapabilities{Available: true, RPID: "example.test"}}
		req, err := Decide(in)
		if err != nil || len(req.Factors) != 1 || req.Factors[0] != "webauthn-roaming" {
			t.Fatalf("%s: %+v %v", provider, req, err)
		}
	}
	in := DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"webauthn-roaming": true}}, Effects: &actionresult.MFAEffects{Mode: "challenge", Factors: [][]string{{"webauthn-roaming"}}}, CustomizeInActions: true, RememberValid: true, SessionMFAAt: time.Now(), WebAuthn: WebAuthnCapabilities{Available: true, RPID: "example.test"}, Authenticators: []store.Authenticator{{Type: "webauthn-roaming", Confirmed: true, RPID: "example.test", CredentialID: []byte{1}, PublicKey: []byte{1}}}}
	req, err := Decide(in)
	if err != nil || !req.Required || req.AllowRemember {
		t.Fatalf("forced MFA %+v %v", req, err)
	}
}

type unavailableWebAuthnStore struct{ store.Store }

func (unavailableWebAuthnStore) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }
func TestWebAuthnUnavailable(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	svc = svc.WithStore(unavailableWebAuthnStore{f.st})
	available, err := svc.WebAuthnAvailable(f.ctx)
	if err != nil || available {
		t.Fatalf("availability=%v err=%v", available, err)
	}
	if _, _, err = svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{}); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("unavailable enroll: %v", err)
	}
	if _, _, err = svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{}); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("unavailable challenge: %v", err)
	}
}

func TestWebAuthnImportedKeyWithoutUserHandle(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{OmitUserHandle: true})
	confirmed, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "ua")
	if err != nil {
		t.Fatal(err)
	}
	// Existing Management-created roaming methods have a key and RP, without
	// a user handle. An MFA assertion may omit its handle for such a method.
	a, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", confirmed.AuthenticatorID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.st.MFA().DeleteAuthenticator(f.ctx, "tenant", "user", a.ID); err != nil {
		t.Fatal(err)
	}
	a.PublicData = nil
	if err = f.st.MFA().CreateAuthenticator(f.ctx, a); err != nil {
		t.Fatal(err)
	}
	c, request, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, key.Get(request, rp.Origin)); err != nil {
		t.Fatal(err)
	}
}

func TestWebAuthnChallengeFiltersOwnedRP(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{})
	confirmed, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "ua")
	if err != nil {
		t.Fatal(err)
	}
	own, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", confirmed.AuthenticatorID)
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"foreign-rp", "other-user", "passkey"} {
		a := *own
		a.ID = NewMethodID(a.Type)
		a.CredentialID = []byte(which)
		switch which {
		case "foreign-rp":
			a.RPID = "foreign.test"
		case "other-user":
			a.UserID = "other"
		case "passkey":
			a.Type = "passkey"
			a.ID = NewMethodID("passkey")
		}
		if err = f.st.MFA().CreateAuthenticator(f.ctx, &a); err != nil {
			t.Fatal(err)
		}
	}
	_, opts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
	if err != nil || len(opts.Allow) != 1 || !bytes.Equal(opts.Allow[0].ID, own.CredentialID) {
		t.Fatalf("owned RP credential list %+v %v", opts.Allow, err)
	}
}

// Registration excludes only this user's credentials for the requested factor
// at this RP; a passkey on the same security key must not prevent MFA setup.
func TestWebAuthnEnrollExcludesOnlyRequestedFactorAtOwnedRP(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	for _, a := range []store.Authenticator{
		{ID: "roaming", UserID: "user", Type: "webauthn-roaming", RPID: "example.test", CredentialID: []byte("roaming")},
		{ID: "passkey", UserID: "user", Type: "passkey", RPID: "example.test", CredentialID: []byte("passkey")},
		{ID: "platform", UserID: "user", Type: "webauthn-platform", RPID: "example.test", CredentialID: []byte("platform")},
		{ID: "foreign", UserID: "user", Type: "webauthn-roaming", RPID: "foreign.test", CredentialID: []byte("foreign")},
		{ID: "other", UserID: "other", Type: "webauthn-roaming", RPID: "example.test", CredentialID: []byte("other")},
	} {
		a.TenantID, a.Confirmed = "tenant", true
		a.PublicData, _ = json.Marshal(map[string]string{"user_handle": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))})
		if err := f.st.MFA().CreateAuthenticator(f.ctx, &a); err != nil {
			t.Fatal(err)
		}
	}
	_, opts, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Exclude) != 1 || !bytes.Equal(opts.Exclude[0].ID, []byte("roaming")) {
		t.Fatalf("requested-factor exclusions = %+v", opts.Exclude)
	}
}

func TestWebAuthnUnavailableCannotEnrollAnotherFactor(t *testing.T) {
	in := DecideInput{Settings: &store.GuardianSettings{Policies: []string{"all-applications"}, Factors: map[string]bool{"otp": true, "webauthn-roaming": true}}, Authenticators: []store.Authenticator{{Type: "webauthn-roaming", Confirmed: true, RPID: "example.test", CredentialID: []byte{1}, PublicKey: []byte{1}}}, WebAuthn: WebAuthnCapabilities{RPID: "example.test"}}
	if req, err := Decide(in); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("unavailable enrolled key must not authorize fresh OTP enrollment: %+v %v", req, err)
	}
}
func TestWebAuthnForeignKeyAllowsFirstOTPEnrollment(t *testing.T) {
	f, svc, _ := roamingFixture(t)
	old := &store.Authenticator{TenantID: "tenant", UserID: "user", ID: NewMethodID("webauthn-roaming"), Type: "webauthn-roaming", Confirmed: true, RPID: "foreign.test", CredentialID: []byte{1}, PublicKey: []byte{1}}
	if err := f.st.MFA().CreateAuthenticator(f.ctx, old); err != nil {
		t.Fatal(err)
	}
	e, err := svc.BeginEnroll(f.ctx, "tenant", "user", "otp", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ConfirmFirstEnroll(f.ctx, "tenant", "user", e, Proof{Code: codeAt(t, e.Secret, f.now)}); err != nil {
		t.Fatalf("foreign RP key blocked current-RP first enrollment: %v", err)
	}
}

// Review finding: the password grant has no RP scope, so a WebAuthn-only user
// must not look unenrolled there (or on any unscoped caller): that would let a
// password alone enroll a fresh factor through /mfa/associate.
func TestUnscopedWebAuthnKeyIsEnrolled(t *testing.T) {
	g := &store.GuardianSettings{Policies: []string{"all-applications"}, Factors: map[string]bool{"otp": true, "webauthn-roaming": true}}
	for _, rp := range []string{"login.custom.example", "example.test"} {
		in := DecideInput{Settings: g, Authenticators: []store.Authenticator{{Type: "webauthn-roaming", Confirmed: true, RPID: rp, CredentialID: []byte{1}, PublicKey: []byte{1}}}}
		if req, err := Decide(in); !errors.Is(err, ErrNoFactor) {
			t.Fatalf("rp %q: password-only enrollment around a security key: %+v %v", rp, req, err)
		}
		in.MFAAPI = true
		if req, err := Decide(in); !errors.Is(err, ErrNoFactor) {
			t.Fatalf("rp %q: MFA API enrollment around a security key: %+v %v", rp, req, err)
		}
		// Availability without an RP scope never makes a key verifiable.
		in.MFAAPI, in.WebAuthn.Available = false, true
		if req, err := Decide(in); !errors.Is(err, ErrNoFactor) {
			t.Fatalf("rp %q: unscoped available: %+v %v", rp, req, err)
		}
	}
}

// Review finding: the held-key guard must not change ordinary factors. An
// Action requesting OTP for an email-only user still enrolls OTP.
func TestActionRequestedFactorStillEnrollsWithoutWebAuthn(t *testing.T) {
	u := &store.User{Email: "a@example.test", EmailVerified: true}
	for _, provider := range []string{"google-authenticator", "guardian"} {
		in := DecideInput{User: u, Settings: &store.GuardianSettings{Factors: map[string]bool{"otp": true, "email": true}}, Effects: &actionresult.MFAEffects{Provider: provider}, Authenticators: []store.Authenticator{{Type: "email", Confirmed: true, Email: "a@example.test"}}}
		req, err := Decide(in)
		if err != nil || !req.Enroll || len(req.Factors) != 1 || req.Factors[0] != "otp" {
			t.Fatalf("%s: %+v %v", provider, req, err)
		}
	}
}

// Review finding: a security key imported through the Management API stores
// neither a user handle nor a captured backup flag. A discoverable key that
// returns its handle, or a multi-device key (BE set), must still verify; a
// stored device type that contradicts the flag still fails.
func TestWebAuthnImportedKeyHandleAndBackupEligibility(t *testing.T) {
	for _, tc := range []struct {
		name   string
		public []byte
		be, ok bool
	}{
		{"no data, handle returned", nil, false, true},
		{"no data, multi-device", nil, true, true},
		{"multi_device", []byte(`{"credential_device_type":"multi_device"}`), true, true},
		{"single_device contradicted", []byte(`{"credential_device_type":"single_device"}`), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, svc, rp := roamingFixture(t)
			e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-roaming", rp, passkey.UserDisplay{})
			if err != nil {
				t.Fatal(err)
			}
			key := webauthntest.New(webauthntest.Options{BE: tc.be})
			confirmed, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Key", "ua")
			if err != nil {
				t.Fatal(err)
			}
			a, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", confirmed.AuthenticatorID)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.st.MFA().DeleteAuthenticator(f.ctx, "tenant", "user", a.ID); err != nil {
				t.Fatal(err)
			}
			a.PublicData = tc.public
			if err = f.st.MFA().CreateAuthenticator(f.ctx, a); err != nil {
				t.Fatal(err)
			}
			c, request, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-roaming", rp, webauthn.Device{})
			if err != nil {
				t.Fatal(err)
			}
			err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, key.Get(request, rp.Origin))
			if tc.ok != (err == nil) {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}
