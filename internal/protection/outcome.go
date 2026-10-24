package protection

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/identity"
)

// CredentialOutcome preserves D-0023 across hosted and direct password flows:
// credential refusals and script-raised failures count; infrastructure failures
// that prevent an answer refund only this attempt's reservation.
func CredentialOutcome(err error) string {
	if err == nil || errors.Is(err, identity.ErrUserBlocked) {
		return "success"
	}
	var refusal *identity.UnauthorizedError
	if errors.Is(err, identity.ErrInvalidCredentials) || errors.Is(err, identity.ErrPasswordChangeRequired) || errors.As(err, &refusal) || identity.ScriptRaised(err) {
		return "failure"
	}
	return "refund"
}
