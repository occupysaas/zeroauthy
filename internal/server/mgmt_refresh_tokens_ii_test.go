package server

import (
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

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

func TestRefreshTokensIIRouteHandlers(t *testing.T) {
	st := memory.New()
	ctx := t.Context()
	at := time.Now().UTC()
	tn := &store.Tenant{ID: "tenant", Name: "acme", Domains: []string{"login.acme.test"}}
	uid := "auth0|000000000000000000000001"
	for _, e := range []error{st.Tenants().Create(ctx, tn), st.Users().Create(ctx, &store.User{TenantID: tn.ID, UserID: uid}), st.RefreshTokens().Create(ctx, &store.RefreshToken{TenantID: tn.ID, UserID: uid, ID: "token-id", TokenHash: "synthetic-hash", FamilyID: "family"}), st.Sessions().Create(ctx, &store.LoginSession{TenantID: tn.ID, UserID: uid, ID: "session-id", TokenHash: "synthetic-session", ExpiresAt: at.Add(time.Hour), IdleExpiresAt: at.Add(time.Hour)})} {
		if e != nil {
			t.Fatal(e)
		}
	}
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{Store: st, Now: func() time.Time { return at }}})
	for _, tc := range []struct {
		method, path, scope, body string
		want                      int
	}{
		{"GET", "/refresh-tokens?user_id=" + url.QueryEscape(uid), "read:refresh_tokens", "", 200},
		{"PATCH", "/refresh-tokens/token-id", "update:refresh_tokens", `{"refresh_token_metadata":{"label":"one"}}`, 200},
		{"PATCH", "/sessions/session-id", "update:sessions", `{"session_metadata":{"label":"two"}}`, 200},
		{"POST", "/refresh-tokens/revoke", "delete:refresh_tokens", `{"ids":["token-id"]}`, 202},
		{"POST", "/sessions/session-id/revoke", "delete:sessions delete:refresh_tokens", `{}`, 202},
	} {
		req := httptest.NewRequest(tc.method, "/api/v2"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(mgmt.WithCaller(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: "login.acme.test"}), mgmt.Caller{Kind: mgmt.M2M, Scopes: strings.Fields(tc.scope)}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s=%d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}
