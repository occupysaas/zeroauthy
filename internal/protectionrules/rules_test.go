package protectionrules

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProtectionRules(t *testing.T) {
	current := Defaults()
	for _, n := range []int{1, 10, 100} {
		out, err := Apply(current, "brute-force-protection", map[string]any{"max_attempts": n})
		if err != nil || out.BruteForce.MaxAttempts != n {
			t.Fatalf("%d: %+v %v", n, out, err)
		}
	}
	for _, p := range []map[string]any{{"max_attempts": 0}, {"max_attempts": 101}, {"max_attempts": 1.5}, {"shields": []string{"admin_notification"}}, {"allowlist": []string{"bogus"}}, {"enabled": nil}, {"unknown": true}} {
		if _, err := Apply(current, "brute-force-protection", p); err == nil {
			t.Fatalf("accepted %v", p)
		}
	}
	out, err := Apply(current, "suspicious-ip-throttling", map[string]any{"allowlist": []string{"192.0.2.0/24", "2001:db8::/32", "::1"}, "stage": map[string]any{"pre-login": map[string]any{"max_attempts": 5}}})
	if err != nil {
		t.Fatal(err)
	}
	if out.SuspiciousIP.Stage.PreLogin.Rate != 864000 || out.SuspiciousIP.Stage.PreUserRegistration.Rate != 1728000 {
		t.Fatal("lost stages")
	}
	if _, err = Apply(current, "suspicious-ip-throttling", map[string]any{"shields": []string{"user_notification"}}); err == nil {
		t.Fatal("cross-feature shield")
	}
	if _, err = Apply(current, "suspicious-ip-throttling", map[string]any{"stage": map[string]any{"future": map[string]any{}}}); err == nil {
		t.Fatal("unknown stage")
	}
	if _, err = Apply(current, "suspicious-ip-throttling", map[string]any{"stage": map[string]any{"pre-custom-token-exchange": map[string]any{"rate": 34560}}}); err != nil {
		t.Fatal(err)
	}
	out.BruteForce.Shields[0] = "changed"
	out.SuspiciousIP.Allowlist[0] = "changed"
	if current.BruteForce.Shields[0] != "block" {
		t.Fatal("clone aliases shields")
	}
	if !reflect.DeepEqual(current, Defaults()) {
		t.Fatal("input changed")
	}
}
func TestProviderRequiredCredentials(t *testing.T) {
	current := Defaults()
	out, err := Apply(current, "captcha", map[string]any{"hcaptcha": map[string]any{"site_key": "site", "secret": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := Apply(out, "captcha", map[string]any{"active_provider_id": "hcaptcha"})
	if err != nil || next.CAPTCHA.HCaptcha.Secret != "secret" {
		t.Fatal("omission lost credential", err)
	}
	if _, err := Apply(out, "captcha", map[string]any{"hcaptcha": map[string]any{"site_key": "other"}}); err == nil {
		t.Fatal("missing required credential accepted")
	}
	if _, err := Apply(out, "captcha", map[string]any{"hcaptcha": map[string]any{"site_key": "site", "secret": ""}}); err != nil {
		t.Fatal("empty secret rejected", err)
	}
	if _, err := Apply(out, "captcha", map[string]any{"hcaptcha": map[string]any{"site_key": "site", "secret": nil}}); err == nil {
		t.Fatal("null secret accepted")
	}
}

func TestProtectionIntegralJSONNumbers(t *testing.T) {
	out, err := Apply(Defaults(), "brute-force-protection", map[string]any{"max_attempts": json.Number("1e1")})
	if err != nil || out.BruteForce.MaxAttempts != 10 {
		t.Fatalf("integral JSON number: %+v %v", out, err)
	}
}

func TestProtectionNullRoot(t *testing.T) {
	if _, err := Apply(Defaults(), "bot-detection", nil); err == nil {
		t.Fatal("null root accepted")
	}
}

func TestProtectionFeatureInventories(t *testing.T) {
	for _, tc := range []struct {
		feature string
		patch   map[string]any
	}{
		{"breached-password-detection", map[string]any{"stage": map[string]any{"pre-change-password": map[string]any{"shields": []string{"user_notification"}}}}},
		{"breached-password-detection", map[string]any{"admin_notification_frequency": []string{"hourly"}}},
		{"bot-detection", map[string]any{"bot_detection_level": "extreme"}},
		{"bot-detection", map[string]any{"challenge_password_policy": "auto"}},
		{"captcha", map[string]any{"active_provider_id": "turnstile"}},
		{"captcha", map[string]any{"recaptcha_enterprise": map[string]any{"site_key": "site", "secret": "wrong", "project_id": "project"}}},
		{"captcha", map[string]any{"auth_challenge": map[string]any{}}},
	} {
		if _, err := Apply(Defaults(), tc.feature, tc.patch); err == nil {
			t.Fatalf("accepted %s %v", tc.feature, tc.patch)
		}
	}
	for _, feature := range []string{"brute-force-protection", "suspicious-ip-throttling", "breached-password-detection", "bot-detection", "captcha"} {
		if _, err := Apply(Defaults(), feature, map[string]any{"unknown": true}); err == nil {
			t.Fatalf("unknown field accepted by %s", feature)
		}
	}
	out, err := Apply(Defaults(), "captcha", map[string]any{"simple_captcha": map[string]any{"future": map[string]any{"array": []any{true}}}})
	if err != nil {
		t.Fatal(err)
	}
	copy := out.Clone()
	copy.CAPTCHA.SimpleCaptcha["future"].(map[string]any)["array"].([]any)[0] = false
	if out.CAPTCHA.SimpleCaptcha["future"].(map[string]any)["array"].([]any)[0] != true {
		t.Fatal("open provider clone aliases nested values")
	}
}
