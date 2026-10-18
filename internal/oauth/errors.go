// internal/oauth/errors.go
package oauth

import (
	"fmt"
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
	// repeated names the parameter a request sent more than once.
	repeated string
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func invalidRequest(desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "invalid_request", Description: desc}
}

// repeatedParam is the invalid_request for a parameter sent more than once.
func repeatedParam(name string) *Error {
	e := invalidRequest(fmt.Sprintf("parameter %q is repeated", name))
	e.repeated = name
	return e
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

// authorizationPending, slowDown, expiredToken and deviceInvalidGrant are
// the device flow's poll answers (RFC 8628 §3.5). Auth0 sends all but
// slow_down with status 403 and invalid_grant here with 403, not 400.
func authorizationPending() *Error {
	return &Error{Status: http.StatusForbidden, Code: "authorization_pending", Description: "the user has not finished authorizing this device yet"}
}

func slowDown() *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: "slow_down", Description: "polling too fast; wait before asking again"}
}

func expiredToken() *Error {
	return &Error{Status: http.StatusForbidden, Code: "expired_token", Description: "the device code has expired; start the flow again"}
}

func deviceInvalidGrant(desc string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "invalid_grant", Description: desc}
}
