package store

import (
	"reflect"
	"testing"
)

func TestLegacyComplexity(t *testing.T) {
	for _, tc := range []struct {
		classes int
		want    PasswordComplexity
	}{
		{-1, PasswordComplexity{MinLength: 9}},
		{0, PasswordComplexity{MinLength: 9}},
		{1, PasswordComplexity{MinLength: 9, MinCharacterClasses: 1}},
		{2, PasswordComplexity{MinLength: 9, MinCharacterClasses: 2}},
		{3, PasswordComplexity{MinLength: 9, CharacterTypes: CharacterTypes, CharacterTypeRule: CharacterTypeRuleThreeOfFour}},
		{4, PasswordComplexity{MinLength: 9, CharacterTypes: CharacterTypes, CharacterTypeRule: CharacterTypeRuleAll}},
		{5, PasswordComplexity{MinLength: 9, CharacterTypes: CharacterTypes, CharacterTypeRule: CharacterTypeRuleAll}},
	} {
		if got := LegacyComplexity(9, tc.classes); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("LegacyComplexity(9, %d) = %+v, want %+v", tc.classes, got, tc.want)
		}
	}
	// The result owns its list: changing it leaves the shared list alone.
	got := LegacyComplexity(0, 4)
	got.CharacterTypes[0] = "changed"
	if CharacterTypes[0] != CharacterTypeUppercase {
		t.Fatal("LegacyComplexity shares CharacterTypes")
	}
}

func TestTenantSettingsClone(t *testing.T) {
	original := &Tenant{SettingsExtra: map[string]any{"nested": map[string]any{"array": []any{map[string]any{"value": "original"}}}}, ProtectionSettings: ProtectionSettings{Bot: BotPolicy{Allowlist: []string{"::1"}}, CAPTCHA: CAPTCHAPolicy{SimpleCaptcha: map[string]any{"nested": []any{map[string]any{"value": "original"}}}}}}
	copy := original.Clone()
	copy.SettingsExtra["nested"].(map[string]any)["array"].([]any)[0].(map[string]any)["value"] = "changed"
	copy.ProtectionSettings.Bot.Allowlist[0] = "changed"
	copy.ProtectionSettings.CAPTCHA.SimpleCaptcha["nested"].([]any)[0].(map[string]any)["value"] = "changed"
	if original.SettingsExtra["nested"].(map[string]any)["array"].([]any)[0].(map[string]any)["value"] != "original" || original.ProtectionSettings.Bot.Allowlist[0] != "::1" || original.ProtectionSettings.CAPTCHA.SimpleCaptcha["nested"].([]any)[0].(map[string]any)["value"] != "original" {
		t.Fatal("clone aliases mutable state")
	}
}
