package mfa

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

const platformUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/130.0 Safari/537.36"

func TestPlatformRules(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	g, _ := f.st.MFA().GetGuardian(f.ctx, "tenant")
	g.Factors["webauthn-platform"] = true
	_ = f.st.MFA().PutGuardian(f.ctx, g, g.Version)
	if _, _, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-platform", rp, passkey.UserDisplay{}); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("platform without another factor: %v", err)
	}
	if err := f.st.MFA().CreateAuthenticator(f.ctx, &store.Authenticator{TenantID: "tenant", UserID: "user", ID: "totp|other", Type: "totp", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	svc = svc.WithPlatformEnrollmentProof()
	e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-platform", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Attachment != "platform" || o.UserVerification != "required" || o.ResidentKey != "discouraged" {
		t.Fatalf("options %+v", o)
	}
	key := webauthntest.New(webauthntest.Options{UV: true, Attachment: "platform"})
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Chrome on macOS", platformUA); err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-platform", rp, webauthn.DeviceOf("Windows Chrome/130")); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("wrong device %v", err)
	}
	c, opts, err := svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-platform", rp, webauthn.DeviceOf(platformUA))
	if err != nil {
		t.Fatal(err)
	}
	key.Opts.UV = false
	if err = svc.VerifyWebAuthn(f.ctx, "tenant", "user", c, key.Get(opts, rp.Origin)); err == nil {
		t.Fatal("UV-less platform proof accepted")
	}
	e, o, err = svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-platform", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key = webauthntest.New(webauthntest.Options{UV: true, Attachment: "platform"})
	if _, err = svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), "Another", platformUA); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("same class %v", err)
	}
	if err = f.st.MFA().DeleteAuthenticator(f.ctx, "tenant", "user", "totp|other"); err != nil {
		t.Fatal(err)
	}
	if _, _, err = svc.BeginWebAuthnChallenge(f.ctx, "tenant", "user", "webauthn-platform", rp, webauthn.DeviceOf(platformUA)); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("only remaining platform offered %v", err)
	}
}
func TestPlatformRulesDecide(t *testing.T) {
	g := &store.GuardianSettings{Factors: map[string]bool{"otp": true, "webauthn-platform": true}, Policies: []string{"all-applications"}}
	in := DecideInput{Settings: g, CustomizeInActions: true, WebAuthn: WebAuthnCapabilities{Available: true, Platform: true, RPID: "example.test", Device: webauthn.DeviceOf(platformUA)}, Effects: &actionresult.MFAEffects{Mode: "enroll", Factors: [][]string{{"webauthn-platform"}}}}
	r, err := Decide(in)
	if err != nil || len(r.Factors) != 1 || r.Factors[0] != "otp" || !r.Enroll {
		t.Fatalf("other enrollment first %+v %v", r, err)
	}
	in.Authenticators = []store.Authenticator{{Type: "totp", Confirmed: true}}
	r, err = Decide(in)
	if err != nil || r.Enroll || len(r.Factors) != 1 || r.Factors[0] != "otp" {
		t.Fatalf("other proof first %+v %v", r, err)
	}
	pub, _ := json.Marshal(map[string]string{"user_agent": platformUA})
	in.Effects = nil
	in.Authenticators = append(in.Authenticators, store.Authenticator{Type: "webauthn-platform", Confirmed: true, RPID: "example.test", CredentialID: []byte{1}, PublicKey: []byte{2}, PublicData: pub})
	r, err = Decide(in)
	if err != nil || len(r.Factors) != 2 {
		t.Fatalf("matching platform %+v %v", r, err)
	}
	in.WebAuthn.Device = webauthn.DeviceOf("Windows Chrome/130")
	r, err = Decide(in)
	if err != nil || len(r.Factors) != 1 || r.Factors[0] != "otp" {
		t.Fatalf("foreign device %+v %v", r, err)
	}
}

func TestPlatformEnrollmentProofAndClassRace(t *testing.T) {
	f, svc, rp := roamingFixture(t)
	g, _ := f.st.MFA().GetGuardian(f.ctx, "tenant")
	g.Factors["webauthn-platform"] = true
	_ = f.st.MFA().PutGuardian(f.ctx, g, g.Version)
	if err := f.st.MFA().CreateAuthenticator(f.ctx, &store.Authenticator{TenantID: "tenant", UserID: "user", ID: "totp|proof", Type: "totp", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-platform", rp, passkey.UserDisplay{}); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("missing trusted proof: %v", err)
	}
	svc = svc.WithPlatformEnrollmentProof()
	enrollments := make([]*Enrollment, 2)
	for i := range enrollments {
		e, o, err := svc.BeginWebAuthnEnroll(f.ctx, "tenant", "user", "webauthn-platform", rp, passkey.UserDisplay{})
		if err != nil {
			t.Fatal(err)
		}
		key := webauthntest.New(webauthntest.Options{UV: true})
		if err = svc.StageWebAuthnEnroll(f.ctx, "tenant", "user", e, key.Create(o, rp.Origin), platformUA); err != nil {
			t.Fatal(err)
		}
		enrollments[i] = e
	}
	results := make(chan error, 2)
	for _, e := range enrollments {
		go func(e *Enrollment) {
			_, err := svc.ConfirmWebAuthnEnroll(f.ctx, "tenant", "user", e, nil, "Device", platformUA)
			results <- err
		}(e)
	}
	wins, refused := 0, 0
	for range enrollments {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, ErrAlreadyEnrolled) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || refused != 1 {
		t.Fatalf("wins=%d refused=%d", wins, refused)
	}
}

func TestPlatformRulesCannotBeOnlyFactor(t *testing.T) {
	pub, _ := json.Marshal(map[string]string{"user_agent": platformUA})
	in := DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"webauthn-platform": true}, Policies: []string{"all-applications"}}, Authenticators: []store.Authenticator{{Type: "webauthn-platform", Confirmed: true, RPID: "example.test", CredentialID: []byte{1}, PublicKey: []byte{2}, PublicData: pub}}, WebAuthn: WebAuthnCapabilities{Available: true, Platform: true, RPID: "example.test", Device: webauthn.DeviceOf(platformUA)}}
	if r, err := Decide(in); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("platform alone %+v %v", r, err)
	}
}

func TestPlatformEnrollWithAnyKeepsAlternatives(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		available, platform, enabled bool
		want                         []string
	}{
		{"available", true, true, true, []string{"otp", "webauthn-platform"}},
		{"no-script", false, false, true, []string{"otp"}},
		{"no-platform", true, false, true, []string{"otp"}},
		{"disabled", true, true, false, []string{"otp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"otp": true, "email": true, "webauthn-platform": tc.enabled}}, CustomizeInActions: true, Effects: &actionresult.MFAEffects{Mode: "enroll", Any: true, Factors: [][]string{{"otp", "webauthn-platform"}}}, WebAuthn: WebAuthnCapabilities{Available: tc.available, Platform: tc.platform, RPID: "example.test", Device: webauthn.DeviceOf(platformUA)}}
			r, err := Decide(in)
			if err != nil || !r.Enroll || r.PlatformAfterProof || !slices.Equal(r.Factors, tc.want) {
				t.Fatalf("requested alternatives: %+v %v; want %v", r, err, tc.want)
			}
		})
	}
}

func TestPlatformEnrollWithAnyFiltersEnrolledAlternatives(t *testing.T) {
	in := DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"otp": true, "email": true, "webauthn-platform": true}}, CustomizeInActions: true, Effects: &actionresult.MFAEffects{Mode: "enroll", Any: true, Factors: [][]string{{"otp", "webauthn-platform"}}}, WebAuthn: WebAuthnCapabilities{Available: true, Platform: true, RPID: "example.test", Device: webauthn.DeviceOf(platformUA)}, Authenticators: []store.Authenticator{{Type: "totp", Confirmed: true}}}
	r, err := Decide(in)
	if err != nil || !r.Enroll || r.PlatformAfterProof || !slices.Equal(r.Factors, []string{"webauthn-platform"}) {
		t.Fatalf("only new requested factor %+v %v", r, err)
	}
	in.WebAuthn.Available = false
	if r, err = Decide(in); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("substituted unrequested enrollment %+v %v", r, err)
	}
	in.WebAuthn.Available = true
	pub, _ := json.Marshal(map[string]string{"user_agent": "Windows Chrome/130"})
	in.Authenticators = []store.Authenticator{{Type: "webauthn-platform", Confirmed: true, RPID: "example.test", CredentialID: []byte{1}, PublicKey: []byte{2}, PublicData: pub}}
	r, err = Decide(in)
	if err != nil || !slices.Equal(r.Factors, []string{"otp"}) {
		t.Fatalf("same device class offered twice %+v %v", r, err)
	}
	in.Authenticators[0].RPID = "foreign.test"
	r, err = Decide(in)
	if err != nil || !slices.Equal(r.Factors, []string{"otp", "webauthn-platform"}) {
		t.Fatalf("foreign RP suppressed enrollment %+v %v", r, err)
	}
}
