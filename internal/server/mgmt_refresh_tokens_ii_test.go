package server

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

func TestRefreshTokensIIRouteScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{}})
	for _, route := range []struct {
		method, path string
		scopes       []string
	}{
		{"GET", "/refresh-tokens?user_id=auth0%7Cuser", []string{"read:refresh_tokens"}},
		{"POST", "/refresh-tokens/revoke", []string{"delete:refresh_tokens"}},
		{"PATCH", "/refresh-tokens/token-id", []string{"update:refresh_tokens"}},
		{"PATCH", "/sessions/session-id", []string{"update:sessions"}},
		{"POST", "/sessions/session-id/revoke", []string{"delete:sessions", "delete:refresh_tokens"}},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, "/api/v2"+route.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("without caller = %d, want 401", rec.Code)
			}
			for i, scope := range route.scopes {
				if !slices.ContainsFunc(tenantsetup.ManagementAPIScopes, func(s store.Scope) bool { return s.Value == scope }) {
					t.Errorf("%s is absent from the Management API scope inventory", scope)
				}
				otherScopes := append([]string{"update:users"}, route.scopes[:i]...)
				otherScopes = append(otherScopes, route.scopes[i+1:]...)
				r := req.WithContext(mgmt.WithCaller(req.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: otherScopes}))
				rec = httptest.NewRecorder()
				h.ServeHTTP(rec, r)
				if rec.Code != http.StatusForbidden {
					t.Errorf("without %s = %d, want 403", scope, rec.Code)
				}
			}
		})
	}
}
