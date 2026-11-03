package mfa

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionresult"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestDecide(t *testing.T) {
	confirmed := []store.Authenticator{{Type: "totp", Confirmed: true}, {Type: "recovery-code", Confirmed: true}}
	for _, tc := range []struct {
		name, policy                                                 string
		effects                                                      *actionresult.MFAEffects
		session, remember, known, required, enroll, always, noFactor bool
		enabled                                                      map[string]bool
		factors                                                      []string
	}{
		{name: "none policy"},
		{name: "policy challenge", policy: "all-applications", required: true, factors: []string{"otp", "recovery-code"}},
		{name: "none overrides policy", policy: "all-applications", effects: &actionresult.MFAEffects{Provider: "none"}},
		{name: "session satisfies", policy: "all-applications", session: true},
		{name: "remember satisfies", policy: "all-applications", remember: true},
		{name: "action ignores remember by default", effects: &actionresult.MFAEffects{Provider: "any"}, remember: true, required: true, factors: []string{"otp", "recovery-code"}},
		{name: "action permits remember", effects: &actionresult.MFAEffects{Provider: "any", AllowRememberBrowser: true}, remember: true},
		{name: "challenge ignores remember and session", effects: &actionresult.MFAEffects{Mode: "challenge", Factors: [][]string{{"otp"}}}, remember: true, session: true, required: true, always: true, factors: []string{"otp"}},
		{name: "enroll always prompts", effects: &actionresult.MFAEffects{Mode: "enroll", Factors: [][]string{{"email"}}}, session: true, required: true, enroll: true, always: true, factors: []string{"email"}},
		{name: "confidence low", policy: "confidence-score", required: true, factors: []string{"otp", "recovery-code"}},
		{name: "confidence known", policy: "confidence-score", known: true},
		{name: "disabled factors fail closed", policy: "all-applications", enabled: map[string]bool{"webauthn-roaming": true}, noFactor: true},
		{name: "duo unavailable", effects: &actionresult.MFAEffects{Provider: "duo"}, noFactor: true},
		{name: "recovery cannot enroll", effects: &actionresult.MFAEffects{Mode: "enroll", Factors: [][]string{{"recovery-code"}}}, noFactor: true},
		{name: "unsupported action fails closed", effects: &actionresult.MFAEffects{Mode: "challenge", Factors: [][]string{{"webauthn-roaming"}}}, noFactor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enabled := tc.enabled
			if enabled == nil {
				enabled = map[string]bool{"otp": true, "email": true, "recovery-code": true}
			}
			in := DecideInput{Settings: &store.GuardianSettings{Factors: enabled}, Effects: tc.effects, Authenticators: confirmed, RememberValid: tc.remember, KnownDevice: tc.known, CustomizeInActions: true}
			if tc.policy != "" {
				in.Settings.Policies = []string{tc.policy}
			}
			if tc.session {
				in.SessionMFAAt = time.Now()
			}
			got, err := Decide(in)
			if tc.noFactor {
				if !errors.Is(err, ErrNoFactor) {
					t.Fatalf("got %v, want ErrNoFactor", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Required != tc.required || got.Enroll != tc.enroll || got.AlwaysPrompt != tc.always {
				t.Fatalf("requirement=%+v", got)
			}
			if tc.required && !reflect.DeepEqual(got.Factors, tc.factors) {
				t.Fatalf("factors=%v want %v", got.Factors, tc.factors)
			}
		})
	}
	t.Run("customization required", func(t *testing.T) {
		_, err := Decide(DecideInput{Effects: &actionresult.MFAEffects{Mode: "challenge", Factors: [][]string{{"otp"}}}})
		if err == nil {
			t.Fatal("accepted disabled action customization")
		}
	})
	t.Run("confidence never enrolls", func(t *testing.T) {
		got, err := Decide(DecideInput{Settings: &store.GuardianSettings{Policies: []string{"confidence-score"}, Factors: map[string]bool{"email": true}}, Authenticators: confirmed})
		if err != nil || got.Required {
			t.Fatalf("got %+v %v", got, err)
		}
	})
}
func TestDecideEnrollWhenNoConfirmedFactor(t *testing.T) {
	got, err := Decide(DecideInput{Settings: &store.GuardianSettings{Policies: []string{"all-applications"}, Factors: map[string]bool{"email": true, "webauthn-platform": true}}, Authenticators: []store.Authenticator{{Type: "totp", Confirmed: true}, {Type: "recovery-code", Confirmed: true}}})
	if err != nil || !got.Required || !got.Enroll || !reflect.DeepEqual(got.Factors, []string{"email"}) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestDecideActionChallengeNeverEnrolls(t *testing.T) {
	_, err := Decide(DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"otp": true}}, Effects: &actionresult.MFAEffects{Mode: "challenge", Factors: [][]string{{"otp"}}}, CustomizeInActions: true})
	if !errors.Is(err, ErrNoFactor) {
		t.Fatalf("challenge with no enrolled factor accepted: %v", err)
	}
}
func TestDecideActionEnrollExcludesEnrolledType(t *testing.T) {
	in := DecideInput{Settings: &store.GuardianSettings{Factors: map[string]bool{"otp": true, "email": true}}, Effects: &actionresult.MFAEffects{Mode: "enroll", Factors: [][]string{{"otp", "email"}}}, Authenticators: []store.Authenticator{{Type: "totp", Confirmed: true}}, CustomizeInActions: true}
	got, err := Decide(in)
	if err != nil || !reflect.DeepEqual(got.Factors, []string{"email"}) {
		t.Fatalf("already enrolled type eligible: %+v %v", got, err)
	}
	in.Effects.Factors = [][]string{{"otp"}}
	if _, err = Decide(in); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("enroll with no new type accepted: %v", err)
	}
}

func TestDecideMFAAPIAudience(t *testing.T) {
	enabled := map[string]bool{"otp": true, "email": true, "recovery-code": true}
	enrolled := []store.Authenticator{{Type: "totp", Confirmed: true}, {Type: "recovery-code", Confirmed: true}}
	for _, tc := range []struct {
		name              string
		list              []store.Authenticator
		effects           *actionresult.MFAEffects
		policy            []string
		session, remember bool
		required          bool
		factors           []string
	}{
		{name: "enrolled without policy", list: enrolled, required: true, factors: []string{"otp", "recovery-code"}},
		{name: "action skip cannot bypass", list: enrolled, effects: &actionresult.MFAEffects{Provider: "none"}, required: true, factors: []string{"otp", "recovery-code"}},
		{name: "remember does not satisfy", list: enrolled, policy: []string{"all-applications"}, remember: true, required: true, factors: []string{"otp", "recovery-code"}},
		{name: "session MFA satisfies", list: enrolled, session: true},
		{name: "unenrolled may enroll with password", list: nil},
		{name: "pending method is not enrolled", list: []store.Authenticator{{Type: "totp"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := DecideInput{Settings: &store.GuardianSettings{Factors: enabled, Policies: tc.policy}, Effects: tc.effects, Authenticators: tc.list, RememberValid: tc.remember, MFAAPI: true}
			if tc.session {
				in.SessionMFAAt = time.Now()
			}
			got, err := Decide(in)
			if err != nil || got.Required != tc.required || tc.required && !reflect.DeepEqual(got.Factors, tc.factors) || tc.required && got.Enroll {
				t.Fatalf("got %+v err %v", got, err)
			}
		})
	}
}
