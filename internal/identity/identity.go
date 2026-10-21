// Package identity authenticates and registers users of database
// connections and throttles failed logins.
package identity

import (
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/loginid"
)

var (
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	ErrUserBlocked        = errors.New("identity: user is blocked")
	// ErrPasswordChangeRequired is a user whose imported hash cannot be
	// verified: whatever password is given, it must be reset first.
	ErrPasswordChangeRequired = errors.New("identity: password change required")
	ErrSignupDisabled         = errors.New("identity: signup is disabled for this connection")
	ErrUserExists             = errors.New("identity: user already exists")
	// ErrScript is a custom database script failure; it wraps the cause.
	ErrScript = errors.New("identity: custom database script failed")
	// ErrScriptUnavailable accompanies ErrScript when the script could not
	// give an answer (timeout, no Node.js, no script, configuration that
	// does not open). Unlike an error the script raised, it does not count
	// as a failed login attempt (D-0023).
	ErrScriptUnavailable = errors.New("identity: custom database script unavailable")
	// ErrPasswordNotChanged is a change_password script reporting false.
	ErrPasswordNotChanged = errors.New("identity: the legacy store did not change the password")
	// ErrPasswordInHistory is the Err of the PolicyError for a password the
	// user had recently.
	ErrPasswordInHistory = errors.New("identity: password was used recently")
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
	// Err, when set, is the sentinel that names the rule (ErrPasswordInHistory).
	Err error
}

func (e *PolicyError) Error() string { return "identity: " + e.Reason }

func (e *PolicyError) Unwrap() error { return e.Err }

const (
	defaultMinPasswordLength = 8
	// MaxPasswordBytes bounds hashing work per request; it is also the most a
	// password_policy min_length can ask for.
	MaxPasswordBytes = 256
)

// NormalizeLogin trims and lowercases an email or username.
func NormalizeLogin(s string) string { return loginid.Normalize(s) }
