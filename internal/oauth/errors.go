// internal/oauth/errors.go
package oauth

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
)

// Error is an OAuth 2.0 error response (RFC 6749 §5.2).
type Error struct {
	Status      int
	Code        string
	Description string
	// basicChallenge adds WWW-Authenticate. RFC 6749 §5.2 requires it when
	// a client that used HTTP Basic fails to authenticate.
	basicChallenge bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func invalidRequest(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_request", Description: desc}
}

func invalidClient(desc string, basic bool) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "invalid_client", Description: desc, basicChallenge: basic}
}

func unauthorizedClient(desc string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "unauthorized_client", Description: desc}
}

func unsupportedGrantType(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "unsupported_grant_type", Description: desc}
}

func invalidScope(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_scope", Description: desc}
}

func accessDenied(desc string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "access_denied", Description: desc}
}

func tooManyRequests() *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Description: "too many attempts; wait a few minutes and try again"}
}

func serverError() *Error {
	return &Error{Status: http.StatusInternalServerError, Code: "server_error", Description: "internal error"}
}

// noStore marks a response as uncacheable (RFC 6749 §5.1).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeError(w http.ResponseWriter, e *Error) {
	noStore(w)
	if e.basicChallenge {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	}
	httpx.WriteError(w, e.Status, e.Code, e.Description)
}

func invalidGrant(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_grant", Description: desc}
}
