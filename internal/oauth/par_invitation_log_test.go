package oauth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// An invitation ticket that is only inside the pushed signed request object
// is registered as a log mask, so no later log carries it.
func TestPARInvitationOnlyInObjectNotLogged(t *testing.T) {
	f := newPKJWTFixture(t)
	f.useJAR(t, "par-web", false)
	const ticket = "ticket-only-in-signed-object"
	obj := jarObject(t, "invitation", ticket)
	var serverLog bytes.Buffer
	logger := slog.New(logscrub.Handler(slog.NewJSONHandler(&serverLog, nil)))
	var tenantEntry []byte
	h := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.h.OauthPar(w, r)
		logger.InfoContext(r.Context(), "later outcome", "detail", "resolved "+ticket)
		doc, err := json.Marshal(map[string]any{"details": map[string]any{"note": "resolved " + ticket}})
		if err != nil {
			t.Fatal(err)
		}
		if tenantEntry, err = logscrub.ScrubContext(r.Context(), doc); err != nil {
			t.Fatal(err)
		}
	}))
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/par", strings.NewReader(jarPARForm(obj).Encode()))
	req.Header.Set("Content-Type", formType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// The request is refused later (no organization); the mask is registered
	// as soon as the object is merged.
	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if strings.Contains(serverLog.String(), ticket) {
		t.Errorf("server log carries the ticket: %s", serverLog.String())
	}
	if strings.Contains(string(tenantEntry), ticket) {
		t.Errorf("tenant log entry carries the ticket: %s", tenantEntry)
	}
}
