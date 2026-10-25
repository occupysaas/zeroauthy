package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestRetiredResourceContracts(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := context.Background()
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := st.ClientGrants().Find(ctx, tn.ID, "m2m", acmeMgmtAPI, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	oldToken := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "m2m", "s3cret")
	noScope, _ := sendJSON(h, http.MethodGet, "https://acme.example.test/api/v2/rules", oldToken, nil)
	if noScope.Code != http.StatusForbidden {
		t.Fatalf("rules without scope = %d %s", noScope.Code, noScope.Body)
	}
	grant.Scopes = append(grant.Scopes, "read:rules", "read:hooks")
	if err := st.ClientGrants().Update(ctx, grant); err != nil {
		t.Fatal(err)
	}
	token := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "m2m", "s3cret")
	for _, target := range []string{"/api/v2/rules?include_totals=true", "/api/v2/rules-configs", "/api/v2/hooks?page=1&per_page=10&include_totals=true"} {
		rec, body := sendJSON(h, http.MethodGet, "https://acme.example.test"+target, token, nil)
		if rec.Code != 200 {
			t.Errorf("GET %s: %d %s", target, rec.Code, rec.Body)
		}
		if strings.Contains(target, "include_totals=true") && (body["total"] != float64(0) || body["limit"] == nil) {
			t.Errorf("totals shape for %s: %v", target, body)
		}
		if target == "/api/v2/rules-configs" && rec.Body.String() != "[]\n" {
			t.Errorf("rules-configs shape: %s", rec.Body)
		}
	}
	for _, path := range []string{"/api/v2/rules", "/api/v2/rules-configs", "/api/v2/hooks"} {
		rec, _ := sendJSON(h, http.MethodPost, "https://acme.example.test"+path, token, map[string]any{"script": "must not persist"})
		if rec.Code >= 200 && rec.Code < 300 {
			t.Errorf("unsupported write %s succeeded: %d", path, rec.Code)
		}
	}
	// The shim remains read-only: no retired endpoint creates stored state.
	for _, path := range []string{"/api/v2/rules", "/api/v2/hooks"} {
		rec, _ := sendJSON(h, http.MethodGet, "https://acme.example.test"+path, token, nil)
		if rec.Code != 200 {
			t.Errorf("GET after rejected writes %s: %d", path, rec.Code)
		}
	}
}
