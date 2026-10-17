// Package authz implements the /authorize endpoint: request validation,
// session checks, login hand-off, code issuance and response delivery.
package authz

// Error is an authorization error (RFC 6749 §4.1.2.1).
type Error struct {
	Code        string
	Description string
}

func errInvalidRequest(d string) *Error     { return &Error{"invalid_request", d} }
func errUnauthorizedClient(d string) *Error { return &Error{"unauthorized_client", d} }
func errAccessDenied(d string) *Error       { return &Error{"access_denied", d} }
func errUnsupportedResponseType(d string) *Error {
	return &Error{"unsupported_response_type", d}
}
func errRequestNotSupported() *Error {
	return &Error{"request_not_supported", "the request parameter (request objects) is not supported"}
}
func errLoginRequired() *Error { return &Error{"login_required", "the user must log in"} }
func errServer() *Error        { return &Error{"server_error", "internal error"} }

func errUserDeclined() *Error {
	return &Error{"access_denied", "the user did not authorize the request"}
}
