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
		policy   store.PasswordPolicy
		password string
		ok       bool
	}{
		{store.PasswordPolicy{}, "1234567", false}, // default minimum is 8
		{store.PasswordPolicy{}, "12345678", true},
		{store.PasswordPolicy{MinLength: 12}, "abcdefghijk", false},
		{store.PasswordPolicy{MinLength: 4}, "ééééé", true}, // runes, not bytes
		{store.PasswordPolicy{RequireCharacterClasses: 3}, "alllowercase", false},
		{store.PasswordPolicy{RequireCharacterClasses: 3}, "Lower1upper", true},
		{store.PasswordPolicy{RequireCharacterClasses: 4}, "Lower1upper!", true},
		{store.PasswordPolicy{}, strings.Repeat("a", MaxPasswordBytes+1), false},
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
