package keys

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
)

func TestCaptchaSecretPatch(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	initial := protectionrules.Defaults()
	patch := map[string]any{"hcaptcha": map[string]any{"site_key": "site", "secret": "private-value"}}
	sealed, err := PatchCAPTCHA(w, "tenant", initial, patch)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sealed)
	if strings.Contains(string(raw), "private-value") {
		t.Fatal("plaintext stored")
	}
	opened, err := OpenCAPTCHA(w, "tenant", sealed.CAPTCHA)
	if err != nil || opened.HCaptcha.Secret != "private-value" {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenCAPTCHA(w, "other", sealed.CAPTCHA); err == nil {
		t.Fatal("cross tenant credential opened")
	}
	swapped := sealed.CAPTCHA
	swapped.RecaptchaV2.Secret = swapped.HCaptcha.Secret
	if _, err := OpenCAPTCHA(w, "tenant", swapped); err == nil {
		t.Fatal("cross provider credential opened")
	}
	preserved, err := PatchCAPTCHA(w, "tenant", sealed, map[string]any{"auth_challenge": map[string]any{"fail_open": false}})
	if err != nil || preserved.CAPTCHA.HCaptcha.Secret != sealed.CAPTCHA.HCaptcha.Secret {
		t.Fatal("omission changed secret", err)
	}
	if _, err := PatchCAPTCHA(w, "tenant", sealed, map[string]any{"hcaptcha": map[string]any{"site_key": "new"}}); err == nil {
		t.Fatal("partial provider accepted")
	}
	cleared, err := PatchCAPTCHA(w, "tenant", sealed, map[string]any{"hcaptcha": map[string]any{"site_key": "site", "secret": ""}})
	if err != nil || cleared.CAPTCHA.HCaptcha.Secret != "" {
		t.Fatal("clear failed", err)
	}
	public, _ := json.Marshal(PublicCAPTCHA(sealed.CAPTCHA))
	if strings.Contains(string(public), "secret") || strings.Contains(string(public), sealed.CAPTCHA.HCaptcha.Secret) {
		t.Fatal("public response leaks secret")
	}
}

func TestCaptchaRequiresActiveCredentials(t *testing.T) {
	w, _ := NewLocalWrapper(testMasterKey(1))
	if _, err := PatchCAPTCHA(w, "t", protectionrules.Defaults(), map[string]any{"active_provider_id": "hcaptcha"}); err == nil {
		t.Fatal("active provider without credentials accepted")
	}
}
