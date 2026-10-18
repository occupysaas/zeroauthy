// Package identity authenticates and registers users of database
// connections and throttles failed logins.
package identity

import (
	"errors"
	"fmt"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/loginid"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	ErrUserBlocked        = errors.New("identity: user is blocked")
	ErrSignupDisabled     = errors.New("identity: signup is disabled for this connection")
	ErrUserExists         = errors.New("identity: user already exists")
	// ErrScript is a custom database script failure; it wraps the cause.
	ErrScript = errors.New("identity: custom database script failed")
	// ErrScriptUnavailable accompanies ErrScript when the script could not
	// give an answer (timeout, no Node.js, no script, configuration that
	// does not open). Unlike an error the script raised, it does not count
	// as a failed login attempt (D-0023).
	ErrScriptUnavailable = errors.New("identity: custom database script unavailable")
	// ErrPasswordNotChanged is a change_password script reporting false.
	ErrPasswordNotChanged = errors.New("identity: the legacy store did not change the password")
)

// UnauthorizedError carries the message of a script's UnauthorizedError,
// which is shown to the user (D-0023).
type UnauthorizedError struct{ Message string }

func (e *UnauthorizedError) Error() string { return "identity: unauthorized: " + e.Message }

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
	// MaxPasswordBytes bounds hashing work per request; it is also the most a
	// password_policy min_length can ask for.
	MaxPasswordBytes = 256
)

// NormalizeLogin trims and lowercases an email or username.
func NormalizeLogin(s string) string { return loginid.Normalize(s) }

// CheckPassword enforces a connection's password complexity: the minimum
// length, the required kinds of character and the longest password.
func CheckPassword(p store.PasswordComplexity, password string) error {
	minLen := p.MinLength
	if minLen <= 0 {
		minLen = defaultMinPasswordLength
	}
	if len(password) > MaxPasswordBytes {
		return &PolicyError{Reason: "password is too long", Key: i18n.KeyPasswordTooLong}
	}
	if utf8.RuneCountInString(password) < minLen {
		return &PolicyError{
			Reason: fmt.Sprintf("password must be at least %d characters", minLen),
			Key:    i18n.KeyPasswordTooShort, Vars: []string{"min", strconv.Itoa(minLen)},
		}
	}
	if len(p.CharacterTypes) == 0 && p.MinCharacterClasses <= 0 {
		return nil
	}
	has := map[string]bool{}
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			has[store.CharacterTypeLowercase] = true
		case unicode.IsUpper(r):
			has[store.CharacterTypeUppercase] = true
		case unicode.IsDigit(r):
			has[store.CharacterTypeNumber] = true
		default:
			has[store.CharacterTypeSpecial] = true
		}
	}
	// need is how many kinds the password must hold; missing is how many
	// it is short of the kinds that are required by name.
	need, short := p.MinCharacterClasses, false
	if len(p.CharacterTypes) > 0 {
		if p.CharacterTypeRule == store.CharacterTypeRuleThreeOfFour {
			need = max(need, 3)
		} else {
			// Every listed type. The message for a subset of the types
			// names the count only.
			need = max(need, len(p.CharacterTypes))
			for _, t := range p.CharacterTypes {
				short = short || !has[t]
			}
		}
	}
	if short || len(has) < need {
		return &PolicyError{
			Reason: fmt.Sprintf(
				"password must contain at least %d of: lowercase letters, uppercase letters, digits, symbols", need),
			Key: i18n.KeyPasswordClasses, Vars: []string{"count", strconv.Itoa(need)},
		}
	}
	return nil
}
