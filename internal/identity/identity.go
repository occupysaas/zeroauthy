// Package identity authenticates and registers users of database
// connections and throttles failed logins.
package identity

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	ErrUserBlocked        = errors.New("identity: user is blocked")
	ErrSignupDisabled     = errors.New("identity: signup is disabled for this connection")
	ErrUserExists         = errors.New("identity: user already exists")
)

// PolicyError explains why input was rejected. Reason is safe to show to
// the person signing up; Key, when set, is the catalog key for a localized
// message and Vars its variables as name, value pairs.
type PolicyError struct {
	Reason, Key string
	Vars        []string
}

func (e *PolicyError) Error() string { return "identity: " + e.Reason }

const (
	defaultMinPasswordLength = 8
	// maxPasswordBytes bounds hashing work per request.
	maxPasswordBytes = 256
)

// NormalizeLogin trims and lowercases an email or username.
func NormalizeLogin(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// CheckPassword enforces a connection's password policy.
func CheckPassword(p store.PasswordPolicy, password string) error {
	minLen := p.MinLength
	if minLen <= 0 {
		minLen = defaultMinPasswordLength
	}
	if len(password) > maxPasswordBytes {
		return &PolicyError{Reason: "password is too long", Key: i18n.KeyPasswordTooLong}
	}
	if utf8.RuneCountInString(password) < minLen {
		return &PolicyError{
			Reason: fmt.Sprintf("password must be at least %d characters", minLen),
			Key:    i18n.KeyPasswordTooShort, Vars: []string{"min", strconv.Itoa(minLen)},
		}
	}
	if p.RequireCharacterClasses > 0 {
		var lower, upper, digit, other bool
		for _, r := range password {
			switch {
			case unicode.IsLower(r):
				lower = true
			case unicode.IsUpper(r):
				upper = true
			case unicode.IsDigit(r):
				digit = true
			default:
				other = true
			}
		}
		n := 0
		for _, b := range []bool{lower, upper, digit, other} {
			if b {
				n++
			}
		}
		if n < p.RequireCharacterClasses {
			return &PolicyError{
				Reason: fmt.Sprintf(
					"password must contain at least %d of: lowercase letters, uppercase letters, digits, symbols",
					p.RequireCharacterClasses),
				Key: i18n.KeyPasswordClasses, Vars: []string{"count", strconv.Itoa(p.RequireCharacterClasses)},
			}
		}
	}
	return nil
}
