package webauthnrules_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

func TestWebAuthnInventory(t *testing.T) {
	rules := webauthnrules.Rules()
	if len(rules) == 0 {
		t.Fatal("no rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" || r.Statement == "" || seen[r.ID] {
			t.Errorf("rule %+v: empty or duplicate", r)
		}
		seen[r.ID] = true
		if !strings.HasPrefix(r.Source, "https://") {
			t.Errorf("rule %s has no source URL", r.ID)
		}
	}
	screens := webauthnrules.Screens()
	if got := screens["passkeys"]; !reflect.DeepEqual(got, []string{"passkey-enrollment", "passkey-enrollment-local"}) {
		t.Errorf("passkeys screens = %v", got)
	}
	wantMFA := []string{
		"mfa-webauthn-change-key-nickname", "mfa-webauthn-enrollment-success", "mfa-webauthn-error",
		"mfa-webauthn-not-available-error", "mfa-webauthn-platform-challenge", "mfa-webauthn-platform-enrollment",
		"mfa-webauthn-roaming-challenge", "mfa-webauthn-roaming-enrollment", "mfa-detect-browser-capabilities",
		"reset-password-mfa-webauthn-platform-challenge", "reset-password-mfa-webauthn-roaming-challenge",
	}
	if got := screens["mfa-webauthn"]; !sameSet(got, wantMFA) {
		t.Errorf("mfa-webauthn screens = %v", got)
	}
	if !slices.Contains(webauthnrules.TextKeys("login-id"), "passkeyButtonText") {
		t.Error("login-id lacks passkeyButtonText")
	}
	for _, k := range []string{"passkey-not-allowed", "no-passkey", "passkey-authentication-failed", "invalid-passkey", "conflict-password-passkey", "password-not-allowed"} {
		if !slices.Contains(webauthnrules.TextKeys("login-id"), k) {
			t.Errorf("login-id lacks error key %s", k)
		}
	}
	if !slices.Contains(webauthnrules.TextKeys("passkey-enrollment"), "passkey-enrollment-max-allowed-reached") {
		t.Error("passkey-enrollment lacks the 20-passkey error key")
	}
	want := webauthnrules.LimitSet{
		MaxPasskeys: 20, HostedChallengeTTL: 5 * time.Minute, NativeTimeout: 60 * time.Second, NativeGrace: 10 * time.Second,
		ProgressiveSnooze: 30 * 24 * time.Hour, LocalSnooze: 30 * 24 * time.Hour, PlatformRemind: 14 * 24 * time.Hour,
		PlatformRefuse: 365 * 24 * time.Hour, NicknameMin: 1, NicknameMax: 20, ChallengeBytes: 32, UserHandleBytes: 32,
		AttestationMax: 64 << 10, ClientDataMax: 16 << 10, CredentialIDMax: 1023, COSEMax: 16 << 10,
		CBORDepth: 16, CBORItems: 1024, RPIDMax: 255,
	}
	if webauthnrules.Limits != want {
		t.Errorf("Limits = %+v", webauthnrules.Limits)
	}
}

func TestWebAuthnLogDetails(t *testing.T) {
	want := map[string][]string{
		"s":                             {"prompts"},
		"ss":                            {"authentication_methods"},
		"gd_enrollment_complete":        {"authenticator"},
		"gd_webauthn_enrollment_failed": {"authentication_methods", "authenticator", "failure_details"},
		"gd_webauthn_challenge_failed":  {"authenticator", "failure_details", "first_factor"},
		"passkey_challenge_started":     {"purpose"},
		"passkey_challenge_failed":      {"purpose"},
	}
	for code, fields := range want {
		if got := webauthnrules.LogDetails(code); !sameSet(got, fields) {
			t.Errorf("LogDetails(%s) = %v, want %v", code, got, fields)
		}
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// plan33bLogCodes are the ten codes Plan 33b took over from earlier plans and
// emits (D-0062).
var plan33bLogCodes = []string{
	"gd_webauthn_enrollment_failed", "gd_webauthn_challenge_failed", "passkey_challenge_started",
	"passkey_challenge_failed", "sepkotpft", "sepkoobft", "sepkrcft", "seotpft", "seoobft", "sercft",
}

func TestPlan33bLogCodes(t *testing.T) {
	byType := map[string]logrules.Code{}
	for _, c := range logrules.Codes() {
		byType[c.Type] = c
	}
	for _, code := range plan33bLogCodes {
		c, ok := byType[code]
		if !ok || c.Plan != 33 || c.Owner != "" {
			t.Errorf("%s = %+v, want Plan 33 without a deferred owner", code, c)
		}
	}
	if c := byType["gd_auth_rejected"]; c.Status != "not_planned" || c.Owner != "" {
		t.Errorf("gd_auth_rejected = %+v, want not_planned without owner", c)
	}
}

// TestPlan33bLogCodesEmitted: every Plan 33b code is recorded as emitted, with
// at least one trigger naming the emitting function.
func TestPlan33bLogCodesEmitted(t *testing.T) {
	byType := map[string]logrules.Code{}
	for _, c := range logrules.Codes() {
		byType[c.Type] = c
	}
	for _, code := range plan33bLogCodes {
		c := byType[code]
		if !c.Emitted || c.Status != "emitted" || len(c.Triggers) == 0 {
			t.Errorf("%s = %+v, want emitted with status emitted and a trigger", code, c)
		}
		for _, tr := range c.Triggers {
			if tr.File == "" || tr.Function == "" {
				t.Errorf("%s trigger %+v incomplete", code, tr)
			}
		}
	}
}
