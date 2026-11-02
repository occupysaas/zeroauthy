package server

import "net/http"

// MFA adapters share the same service instance as hosted login.
func mfaUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"error":"mfa_unavailable"}`))
}

func (a authAPI) MFAAssociate(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		mfaUnavailable(w)
		return
	}
	a.oauth.MFAAssociate(w, r)
}
func (a authAPI) MFAListAuthenticators(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		mfaUnavailable(w)
		return
	}
	a.oauth.MFAListAuthenticators(w, r)
}
func (a authAPI) MFADeleteAuthenticator(w http.ResponseWriter, r *http.Request, id string) {
	if a.oauth == nil {
		mfaUnavailable(w)
		return
	}
	a.oauth.MFADeleteAuthenticator(w, r, id)
}
func (a authAPI) MFAChallenge(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		mfaUnavailable(w)
		return
	}
	a.oauth.MFAChallenge(w, r)
}
