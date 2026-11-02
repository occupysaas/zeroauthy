package server

import "net/http"

// These adapters keep generated routes unavailable until the MFA service lands.
func mfaUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"error":"mfa_unavailable"}`))
}
func (authAPI) MFAAssociate(w http.ResponseWriter, _ *http.Request)          { mfaUnavailable(w) }
func (authAPI) MFAListAuthenticators(w http.ResponseWriter, _ *http.Request) { mfaUnavailable(w) }
func (authAPI) MFADeleteAuthenticator(w http.ResponseWriter, _ *http.Request, _ string) {
	mfaUnavailable(w)
}
func (authAPI) MFAChallenge(w http.ResponseWriter, _ *http.Request) { mfaUnavailable(w) }
