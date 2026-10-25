// Package protectionrules validates the five public attack-protection policies.
package protectionrules

import (
	"bytes"
	"encoding/json"

	"github.com/zeroauthy/zeroauthy/internal/settingsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Error = settingsrules.Error

var schemas = settingsrules.ParseFeatures(inventory)

// Defaults follows A1 and D-0045. Breach detection is locally disabled until an
// operator supplies a checker; this is not Auth0's enabled schema annotation.
func Defaults() store.ProtectionSettings {
	return store.ProtectionSettings{
		BruteForce:       store.BruteForcePolicy{Enabled: true, Shields: []string{"block", "user_notification"}, Allowlist: []string{}, Mode: "count_per_identifier_and_ip", MaxAttempts: 10, FormSubmissionMode: "auto"},
		SuspiciousIP:     store.SuspiciousIPPolicy{Enabled: true, Shields: []string{"admin_notification", "block"}, Allowlist: []string{}, Stage: store.SuspiciousIPStages{PreLogin: store.ProtectionRate{MaxAttempts: 100, Rate: 864000}, PreUserRegistration: store.ProtectionRate{MaxAttempts: 50, Rate: 1728000}, PreCustomTokenExchange: store.ProtectionRate{MaxAttempts: 10, Rate: 8640000}}},
		BreachedPassword: store.BreachedPasswordPolicy{Enabled: false, Shields: []string{}, AdminNotificationFrequency: []string{}, Method: "standard", Stage: store.BreachedPasswordStages{PreUserRegistration: store.ProtectionShields{Shields: []string{}}, PreChangePassword: store.ProtectionShields{Shields: []string{}}}},
		Bot:              store.BotPolicy{BotDetectionLevel: "medium", ChallengePasswordPolicy: "never", ChallengePasswordlessPolicy: "never", ChallengePasswordResetPolicy: "never", Allowlist: []string{}},
		CAPTCHA:          store.CAPTCHAPolicy{ActiveProviderID: "auth_challenge", SimpleCaptcha: map[string]any{}},
	}
}

// Apply validates supplied objects before merging so provider required fields
// cannot be satisfied by credentials from the prior policy. Omitted provider
// objects preserve credentials. Empty strings explicitly clear credentials.
func Apply(current store.ProtectionSettings, feature string, patch map[string]any) (store.ProtectionSettings, error) {
	if patch == nil {
		return current, settingsrules.Invalid("", "null is not allowed")
	}
	schema, ok := schemas[feature]
	if !ok {
		return current, settingsrules.Invalid("feature", "unknown protection feature")
	}
	if err := schema.Validate(patch, ""); err != nil {
		return current, err
	}
	out := current.Clone()
	var target any
	switch feature {
	case "brute-force-protection":
		target = &out.BruteForce
	case "suspicious-ip-throttling":
		target = &out.SuspiciousIP
	case "breached-password-detection":
		target = &out.BreachedPassword
	case "bot-detection":
		target = &out.Bot
	case "captcha":
		target = &out.CAPTCHA
	}
	data, err := json.Marshal(target)
	if err != nil {
		return current, settingsrules.Invalid("", "invalid stored policy")
	}
	var before map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&before); err != nil {
		return current, err
	}
	merged := settingsrules.Merge(before, schema.Normalize(patch).(map[string]any))
	data, err = json.Marshal(merged)
	if err != nil {
		return current, settingsrules.Invalid("", "invalid policy value")
	}
	// Preserve arbitrary provider JSON numbers as well as typed integer fields.
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return current, settingsrules.Invalid("", "invalid policy value")
	}
	// An explicit edit moves that feature away from legacy compatibility mode.
	if feature == "brute-force-protection" && len(patch) > 0 {
		out.LegacyLockoutSeconds = 0
		out.LegacyIPMaxAttempts = 0
	}
	if feature == "suspicious-ip-throttling" && len(patch) > 0 {
		out.LegacyIPMaxAttempts = 0
	}
	return out, nil
}
