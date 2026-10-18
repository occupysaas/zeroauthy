package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestNormalizeLogin(t *testing.T) {
	if got := NormalizeLogin("  Alice@Example.COM \t"); got != "alice@example.com" {
		t.Fatalf("NormalizeLogin = %q", got)
	}
}

func TestCheckPassword(t *testing.T) {
	cases := []struct {
		policy   store.PasswordComplexity
		password string
		ok       bool
	}{
		{store.PasswordComplexity{}, "1234567", false}, // default minimum is 8
		{store.PasswordComplexity{}, "12345678", true},
		{store.PasswordComplexity{MinLength: 12}, "abcdefghijk", false},
		{store.PasswordComplexity{MinLength: 4}, "ééééé", true}, // runes, not bytes
		{store.LegacyComplexity(0, 3), "alllowercase", false},
		{store.LegacyComplexity(0, 3), "Lower1upper", true},
		{store.LegacyComplexity(0, 4), "Lower1upper!", true},
		{store.PasswordComplexity{}, strings.Repeat("a", MaxPasswordBytes+1), false},
		{store.LegacyComplexity(0, 1), "12345678", true}, // any one class
		{store.LegacyComplexity(0, 2), "12345678", false},
		{store.LegacyComplexity(0, 2), "abcdef12", true},
		{store.LegacyComplexity(0, 4), "Lower1upper", false},
		{store.LegacyComplexity(0, 3), "Lower1upper", true},
		{store.LegacyComplexity(0, 3), "lower1upper!", true},
		// Required types by name.
		{store.PasswordComplexity{CharacterTypes: []string{"number"}}, "abcdefgh", false},
		{store.PasswordComplexity{CharacterTypes: []string{"number"}}, "abcdefg1", true},
		{store.PasswordComplexity{CharacterTypes: []string{"uppercase", "special"}, CharacterTypeRule: "all"}, "Abcdefgh1", false},
		{store.PasswordComplexity{CharacterTypes: []string{"uppercase", "special"}, CharacterTypeRule: "all"}, "Abcdefgh!", true},
	}
	for _, tc := range cases {
		err := CheckPassword(tc.policy, tc.password)
		if (err == nil) != tc.ok {
			t.Errorf("CheckPassword(%+v, %q) = %v, want ok=%v", tc.policy, tc.password, err, tc.ok)
		}
		var pe *PolicyError
		if err != nil && !errors.As(err, &pe) {
			t.Errorf("error %v is not a *PolicyError", err)
		}
	}
}

func TestCheckUsername(t *testing.T) {
	for _, ok := range []string{"alice", "a.b_c+d-e", strings.Repeat("a", 64)} {
		if err := CheckUsername(ok); err != nil {
			t.Errorf("CheckUsername(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "victim@acme.test", "has space", strings.Repeat("a", 65)} {
		var pe *PolicyError
		if err := CheckUsername(bad); !errors.As(err, &pe) {
			t.Errorf("CheckUsername(%q) = %v, want a PolicyError", bad, err)
		}
	}
}
