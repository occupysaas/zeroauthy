package authz

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
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

// An invitation ticket that arrives only inside the signed request object is
// registered as a log mask, so neither the server log nor a tenant log entry
// written with the request context carries it.
func TestJARInvitationOnlyInObjectNotLogged(t *testing.T) {
	e := newJAREnv(t, false)
	const ticket = "ticket-only-in-signed-object"
	obj := signJAR(t, jarKey(t, "rsa2048.priv.pem"), jarClaims("invitation", ticket, "organization", "org_x"))
	var serverLog bytes.Buffer
	logger := slog.New(logscrub.Handler(slog.NewJSONHandler(&serverLog, nil)))
	var tenantEntry []byte
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.h.Authorize(w, r)
		logger.InfoContext(r.Context(), "later outcome", "detail", "resolved "+ticket)
		doc, err := json.Marshal(map[string]any{"details": map[string]any{"note": "resolved " + ticket}})
		if err != nil {
			t.Fatal(err)
		}
		if tenantEntry, err = logscrub.ScrubContext(r.Context(), doc); err != nil {
			t.Fatal(err)
		}
	})
	srv := contract.Wrap(t, tenant.NewResolver(e.st.Tenants(), "", false).Middleware(inner))
	srv.ServeHTTP(httptest.NewRecorder(), httptestRequest("https://acme.example.test/authorize?"+jarQuery(obj).Encode()))
	if serverLog.Len() == 0 || len(tenantEntry) == 0 {
		t.Fatalf("nothing captured: %q %q", serverLog.String(), tenantEntry)
	}
	if strings.Contains(serverLog.String(), ticket) {
		t.Errorf("server log carries the ticket: %s", serverLog.String())
	}
	if strings.Contains(string(tenantEntry), ticket) {
		t.Errorf("tenant log entry carries the ticket: %s", tenantEntry)
	}
}
