package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMFABridgeUnavailable(t *testing.T) {
	a := authAPI{}
	cases := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{{"associate", a.MFAAssociate}, {"list", a.MFAListAuthenticators}, {"delete", func(w http.ResponseWriter, r *http.Request) { a.MFADeleteAuthenticator(w, r, "id") }}, {"challenge", a.MFAChallenge}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.call(w, httptest.NewRequest("GET", "/", nil))
			if w.Code != http.StatusNotImplemented || !strings.Contains(w.Body.String(), "mfa_unavailable") {
				t.Fatalf("response: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
