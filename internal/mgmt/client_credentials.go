package mgmt

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// errClientCredentialsUnavailable answers the client credential and token
// exchange profile routes. It is the permanent answer for a storage plugin
// without the client_credentials.v1 capability; until the Plan 35 tasks land
// every store answers it (D-0063).
var errClientCredentialsUnavailable = &Error{Status: http.StatusNotImplemented, Code: "client_credentials_unavailable", Message: "Client credentials are not available with this storage plugin"}

// The handlers below are Task 1 stubs of Plan 35 that freeze the contract;
// each is replaced by its implementation in a later task.

// GetClientCredentials lists an application's credentials.
func (h *Handlers) GetClientCredentials(w http.ResponseWriter, r *http.Request, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// PostClientCredentials adds a credential to an application.
func (h *Handlers) PostClientCredentials(w http.ResponseWriter, r *http.Request, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// GetClientCredential returns one credential.
func (h *Handlers) GetClientCredential(w http.ResponseWriter, r *http.Request, _, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// PatchClientCredential changes a credential's expiry.
func (h *Handlers) PatchClientCredential(w http.ResponseWriter, r *http.Request, _, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// DeleteClientCredential removes a credential.
func (h *Handlers) DeleteClientCredential(w http.ResponseWriter, r *http.Request, _, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// GetTokenExchangeProfiles lists token exchange profiles.
func (h *Handlers) GetTokenExchangeProfiles(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetTokenExchangeProfilesParams) {
	Fail(w, errClientCredentialsUnavailable)
}

// PostTokenExchangeProfile creates a token exchange profile.
func (h *Handlers) PostTokenExchangeProfile(w http.ResponseWriter, r *http.Request) {
	Fail(w, errClientCredentialsUnavailable)
}

// GetTokenExchangeProfile returns one token exchange profile.
func (h *Handlers) GetTokenExchangeProfile(w http.ResponseWriter, r *http.Request, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// PatchTokenExchangeProfile updates a token exchange profile.
func (h *Handlers) PatchTokenExchangeProfile(w http.ResponseWriter, r *http.Request, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}

// DeleteTokenExchangeProfile removes a token exchange profile.
func (h *Handlers) DeleteTokenExchangeProfile(w http.ResponseWriter, r *http.Request, _ string) {
	Fail(w, errClientCredentialsUnavailable)
}
