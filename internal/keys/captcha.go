package keys

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const captchaPrefix = "zcap1."

func captchaCredentials(c *store.CAPTCHAPolicy) map[string]*string {
	return map[string]*string{"arkose.secret": &c.Arkose.Secret, "hcaptcha.secret": &c.HCaptcha.Secret, "friendly_captcha.secret": &c.FriendlyCaptcha.Secret, "recaptcha_v2.secret": &c.RecaptchaV2.Secret, "recaptcha_enterprise.api_key": &c.RecaptchaEnterprise.APIKey}
}

// PatchCAPTCHA accepts a plaintext public patch and an encrypted stored policy.
// Only supplied credentials are sealed. Omitted provider blobs remain unchanged.
// Callers persist the result, never the plaintext patch or OpenCAPTCHA result.
func PatchCAPTCHA(w Wrapper, tenantID string, stored store.ProtectionSettings, patch map[string]any) (store.ProtectionSettings, error) {
	out, err := protectionrules.Apply(stored, "captcha", patch)
	if err != nil {
		return stored, err
	}

	c := out.CAPTCHA
	ready := true
	switch c.ActiveProviderID {
	case "arkose":
		ready = c.Arkose.SiteKey != "" && c.Arkose.Secret != ""
	case "hcaptcha":
		ready = c.HCaptcha.SiteKey != "" && c.HCaptcha.Secret != ""
	case "friendly_captcha":
		ready = c.FriendlyCaptcha.SiteKey != "" && c.FriendlyCaptcha.Secret != ""
	case "recaptcha_v2":
		ready = c.RecaptchaV2.SiteKey != "" && c.RecaptchaV2.Secret != ""
	case "recaptcha_enterprise":
		ready = c.RecaptchaEnterprise.SiteKey != "" && c.RecaptchaEnterprise.APIKey != "" && c.RecaptchaEnterprise.ProjectID != ""
	}
	if !ready {
		return stored, errors.New("keys: active CAPTCHA provider requires complete credentials")
	}
	for field, value := range captchaCredentials(&out.CAPTCHA) {
		provider, _, _ := strings.Cut(field, ".")
		if _, present := patch[provider]; !present || *value == "" {
			continue
		}
		if w == nil {
			return stored, errors.New("keys: CAPTCHA requires a master key wrapper")
		}
		blob, err := seal(w, []byte(*value), lengthPrefixed("captcha/v1", tenantID, field))
		if err != nil {
			return stored, errors.New("keys: seal CAPTCHA credential")
		}
		*value = captchaPrefix + base64.RawURLEncoding.EncodeToString(blob)
	}
	return out, nil
}

// OpenCAPTCHA returns a transient copy for provider verification only. Errors
// never contain credential material. Ciphertexts are tenant/provider/field bound.
func OpenCAPTCHA(w Wrapper, tenantID string, stored store.CAPTCHAPolicy) (store.CAPTCHAPolicy, error) {
	out := stored
	for field, value := range captchaCredentials(&out) {
		if *value == "" {
			continue
		}
		encoded, ok := strings.CutPrefix(*value, captchaPrefix)
		if !ok || w == nil {
			return store.CAPTCHAPolicy{}, errors.New("keys: invalid CAPTCHA credential envelope")
		}
		blob, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return store.CAPTCHAPolicy{}, errors.New("keys: invalid CAPTCHA credential envelope")
		}
		plain, err := unseal(w, blob, lengthPrefixed("captcha/v1", tenantID, field))
		if err != nil {
			return store.CAPTCHAPolicy{}, errors.New("keys: CAPTCHA credential does not open")
		}
		*value = string(plain)
	}
	return out, nil
}

// PublicCAPTCHA explicitly removes all credential fields, including encrypted
// blobs. Use this serializer for public GET/PATCH responses, never raw models.
func PublicCAPTCHA(stored store.CAPTCHAPolicy) map[string]any {
	raw, _ := json.Marshal(stored)
	var out map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	_ = decoder.Decode(&out)
	for field := range captchaCredentials(&stored) {
		provider, child, _ := strings.Cut(field, ".")
		if object, ok := out[provider].(map[string]any); ok {
			delete(object, child)
		}
	}
	return out
}
