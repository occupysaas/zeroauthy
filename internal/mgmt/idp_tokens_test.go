package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const idpAccess, idpRefresh = "upstream-access-AAA", "upstream-refresh-BBB"

func (e *usersEnv) socialUser(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	g := &store.Connection{TenantID: e.tn.ID, ID: "con_google", Name: "google-oauth2", Strategy: "google-oauth2", CreatedAt: now}
	if err := e.st.Connections().Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: "google-oauth2|S1", Email: "s@x.test",
		Identities: []store.Identity{{Connection: g.Name, Provider: "google-oauth2", UserID: "S1"}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	key := store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: g.ID, Subject: "S1"}
	sealed, err := federation.SealTokens(e.w, key, federation.TokenSet{AccessToken: idpAccess, RefreshToken: idpRefresh, TokenType: "Bearer"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Federation().PutTokens(ctx, key, sealed); err != nil {
		t.Fatal(err)
	}
	return "google-oauth2|S1"
}

func (e *usersEnv) getUser(t *testing.T, caller mgmt.Caller, id string) (int, string, http.Header) {
	t.Helper()
	rec, _ := e.do(t, caller, "GET", "/api/v2/users/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUser(w, r, id, mgmtapi.GetUserParams{})
	})
	return rec.Code, rec.Body.String(), rec.Header()
}

func TestIDPTokenProjection(t *testing.T) {
	e := newUsersEnv(t)
	id := e.socialUser(t)

	code, body, _ := e.getUser(t, m2mCaller("read:users"), id)
	if code != 200 || strings.Contains(body, "access_token") || strings.Contains(body, idpAccess) {
		t.Fatalf("no token scope: %d %s", code, body)
	}
	code, body, h := e.getUser(t, m2mCaller("read:users", "read:user_idp_tokens"), id)
	if code != 200 || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("scoped get: %d %v", code, h)
	}
	var u map[string]any
	_ = json.Unmarshal([]byte(body), &u)
	ident := u["identities"].([]any)[0].(map[string]any)
	if ident["access_token"] != idpAccess || ident["refresh_token"] != idpRefresh || ident["isSocial"] != true {
		t.Fatalf("identity %v", ident)
	}
	// Operators (the console) never see upstream tokens, whatever scopes
	// they hold.
	code, body, _ = e.getUser(t, mgmt.Caller{Kind: mgmt.Operator, UserID: "op"}, id)
	if code != 200 || strings.Contains(body, idpAccess) {
		t.Fatalf("operator: %d %s", code, body)
	}
	// Lists, search by email and link responses never carry them.
	both := m2mCaller("read:users", "read:user_idp_tokens", "update:users")
	rec, _ := e.do(t, both, "GET", "/api/v2/users", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetUsers(w, r, mgmtapi.GetUsersParams{}) })
	if rec.Code != 200 || strings.Contains(rec.Body.String(), idpAccess) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.do(t, both, "GET", "/api/v2/users-by-email?email=s@x.test", nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUsersByEmail(w, r, mgmtapi.GetUsersByEmailParams{})
	})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), idpAccess) {
		t.Fatalf("by email: %d %s", rec.Code, rec.Body)
	}
	if b, _ := json.Marshal(mgmt.UserJSON(&store.User{UserID: id, Identities: []store.Identity{{Provider: "google-oauth2", UserID: "S1"}}})); strings.Contains(string(b), "access_token") {
		t.Fatal("generic user projection has token fields")
	}
	// A missing token record omits the fields rather than failing.
	_ = e.st.Federation().DeleteTokens(context.Background(), store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: "con_google", Subject: "S1"})
	if code, body, _ := e.getUser(t, m2mCaller("read:users", "read:user_idp_tokens"), id); code != 200 || strings.Contains(body, "access_token") {
		t.Fatalf("missing record: %d %s", code, body)
	}
}

// Registering the scope does not grant it to grants that allow all scopes.
func TestIDPTokenScopeNotImplied(t *testing.T) {
	if !tenantsetup.IsManagementAPIScope("read:user_idp_tokens") {
		t.Fatal("scope not registered")
	}
	g := &store.ClientGrant{AllowAllScopes: true}
	for _, s := range g.EffectiveScopes(tenantsetup.ManagementAPIScopes) {
		if s == "read:user_idp_tokens" {
			t.Fatal("allow_all_scopes implies read:user_idp_tokens")
		}
	}
}
