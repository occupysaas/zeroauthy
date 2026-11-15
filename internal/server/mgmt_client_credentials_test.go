package server

import (
	"net/http/httptest"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

// TestClientCredentialsScopes: each credential route refuses a token without
// its scope (403) and a request without a token (401). The scope check runs
// before the handler, so no store is needed.
func TestClientCredentialsScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, item := range []struct {
		method, path string
		scopes       []string // any one of these lets the request through
	}{
		{"GET", "", []string{"read:client_credentials"}},
		{"POST", "", []string{"create:client_credentials"}},
		{"GET", "/cred_0000000000000000000001", []string{"read:client_credentials"}},
		{"PATCH", "/cred_0000000000000000000001", []string{"update:credentials", "update:client_credentials"}},
		{"DELETE", "/cred_0000000000000000000001", []string{"delete:client_credentials"}},
	} {
		target := "/api/v2/clients/abc/credentials" + item.path
		r := httptest.NewRequest(item.method, target, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("%s %s without a token = %d, want 401", item.method, target, w.Code)
		}
		// A token with every other scope but this route's is refused.
		r = httptest.NewRequest(item.method, target, nil)
		r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: []string{
			"read:clients", "update:clients", "create:clients", "delete:clients", "read:client_keys",
			"read:client_grants", "create:client_grants", "update:client_grants", "delete:client_grants",
		}}))
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("%s %s with other scopes = %d, want 403", item.method, target, w.Code)
		}
	}
}
