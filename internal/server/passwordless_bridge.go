package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
)

// Passwordless routes are frozen by Plan 34 Task 1; the service lands in
// Task 10. Until then they fail closed with 501, like the MFA bridge did.
func passwordlessUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"error":"passwordless_unavailable","error_description":"Passwordless authentication is not available."}`))
}

func (a authAPI) PasswordlessStart(w http.ResponseWriter, _ *http.Request, _ authapi.PasswordlessStartParams) {
	passwordlessUnavailable(w)
}

func (a authAPI) PasswordlessVerifyRedirect(w http.ResponseWriter, _ *http.Request, _ authapi.PasswordlessVerifyRedirectParams) {
	passwordlessUnavailable(w)
}

func (a authAPI) PasswordlessVerifyRedirectConfirm(w http.ResponseWriter, _ *http.Request) {
	passwordlessUnavailable(w)
}
