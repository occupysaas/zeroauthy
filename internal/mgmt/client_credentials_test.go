package mgmt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// Until their tasks land, the Plan 35 routes answer 501 (D-0063).
func TestClientCredentialRoutesAnswerNotImplemented(t *testing.T) {
	h := &Handlers{}
	routes := map[string]func(http.ResponseWriter, *http.Request){
		"GetClientCredentials":   func(w http.ResponseWriter, r *http.Request) { h.GetClientCredentials(w, r, "c") },
		"PostClientCredentials":  func(w http.ResponseWriter, r *http.Request) { h.PostClientCredentials(w, r, "c") },
		"GetClientCredential":    func(w http.ResponseWriter, r *http.Request) { h.GetClientCredential(w, r, "c", "cred_x") },
		"PatchClientCredential":  func(w http.ResponseWriter, r *http.Request) { h.PatchClientCredential(w, r, "c", "cred_x") },
		"DeleteClientCredential": func(w http.ResponseWriter, r *http.Request) { h.DeleteClientCredential(w, r, "c", "cred_x") },
		"GetTokenExchangeProfiles": func(w http.ResponseWriter, r *http.Request) {
			h.GetTokenExchangeProfiles(w, r, mgmtapi.GetTokenExchangeProfilesParams{})
		},
		"PostTokenExchangeProfile":   h.PostTokenExchangeProfile,
		"GetTokenExchangeProfile":    func(w http.ResponseWriter, r *http.Request) { h.GetTokenExchangeProfile(w, r, "tep_x") },
		"PatchTokenExchangeProfile":  func(w http.ResponseWriter, r *http.Request) { h.PatchTokenExchangeProfile(w, r, "tep_x") },
		"DeleteTokenExchangeProfile": func(w http.ResponseWriter, r *http.Request) { h.DeleteTokenExchangeProfile(w, r, "tep_x") },
	}
	for name, route := range routes {
		rec := httptest.NewRecorder()
		route(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s: status %d, want 501", name, rec.Code)
		}
	}
}
