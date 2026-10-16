package customdb

import (
	"errors"
	"fmt"
	"time"
)

// Kinds of ScriptError, from the error class a script passed to its callback.
const (
	KindWrongCredentials = "wrong_credentials" // WrongUsernameOrPasswordError
	KindValidation       = "validation"        // ValidationError
	KindUnauthorized     = "unauthorized"      // UnauthorizedError
	KindError            = "error"             // anything else, including thrown exceptions
)

var (
	ErrTimeout     = errors.New("customdb: script timed out")
	ErrUnavailable = errors.New("customdb: script runtime unavailable") // node missing, too old, crashed
	ErrNoScript    = errors.New("customdb: script not configured")
)

// MaxDuration bounds one script execution. When it is exceeded the tenant's
// runner process is killed.
const MaxDuration = 20 * time.Second

// ScriptError is an error the script passed to its callback (or threw).
type ScriptError struct {
	Kind    string // KindWrongCredentials | KindValidation | KindUnauthorized | KindError
	Code    string // ValidationError code; WrongUsernameOrPasswordError identifier
	Message string // the script's message; safe to log, shown to users only for KindUnauthorized
}

func (e *ScriptError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("customdb: script error (%s, %s): %s", e.Kind, e.Code, e.Message)
	}
	return fmt.Sprintf("customdb: script error (%s): %s", e.Kind, e.Message)
}
