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
