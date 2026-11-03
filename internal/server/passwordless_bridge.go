package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
)

// The passwordless routes (Plan 34): /passwordless/start is served by the
// OAuth handlers (client authentication), verify_redirect by the passwordless
// handlers (browser verification and authorization continuation).

func (a authAPI) PasswordlessStart(w http.ResponseWriter, r *http.Request, _ authapi.PasswordlessStartParams) {
	a.oauth.PasswordlessStart(w, r)
}

func (a authAPI) PasswordlessVerifyRedirect(w http.ResponseWriter, r *http.Request, _ authapi.PasswordlessVerifyRedirectParams) {
	a.passwordless.VerifyRedirect(w, r)
}

func (a authAPI) PasswordlessVerifyRedirectConfirm(w http.ResponseWriter, r *http.Request) {
	a.passwordless.VerifyRedirectConfirm(w, r)
}
