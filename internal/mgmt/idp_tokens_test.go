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
	return e.providerUser(t, "google-oauth2", nil, "S1")
}
func (e *usersEnv) providerUser(t *testing.T, provider string, extra map[string]any, sub string) string {
	t.Helper()
	ctx := context.Background()
	g := &store.Connection{TenantID: e.tn.ID, ID: "con_google", Name: "provider", Strategy: provider, Extra: extra, CreatedAt: now}
	if err := e.st.Connections().Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	identityID := sub
	if provider == "waad" {
		identityID = g.Name + "|" + sub
	}
	publicID := store.FederatedPublicID(provider, g.Name, sub)
	if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: publicID, Email: "s@x.test",
		Identities: []store.Identity{{Connection: g.Name, Provider: provider, UserID: identityID}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	key := store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: g.ID, Subject: sub}
	sealed, err := federation.SealTokens(e.w, key, federation.TokenSet{AccessToken: idpAccess, RefreshToken: idpRefresh, TokenType: "Bearer"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Federation().PutTokens(ctx, key, sealed); err != nil {
		t.Fatal(err)
	}
	return publicID
}

func (e *usersEnv) getUser(t *testing.T, caller mgmt.Caller, id string) (int, string, http.Header) {
	t.Helper()
	rec, _ := e.do(t, caller, "GET", "/api/v2/users/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetUser(w, r, id, mgmtapi.GetUserParams{})
	})
	return rec.Code, rec.Body.String(), rec.Header()
}

func TestIDPTokenProjection(t *testing.T) { idpTokenProjection(t, "google-oauth2", nil, "S1", true) }
func TestMicrosoftTokenProjection(t *testing.T) {
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const tid = "11111111-2222-3333-4444-555555555555"
	for _, tc := range []struct {
		name, provider, sub string
		extra               map[string]any
		social              bool
	}{
		{"personal", "windowslive", "CaseSensitive", nil, true},
		{"single", "waad", oid, map[string]any{"tenant_domain": tid}, false},
		{"multi", "waad", tid + ":" + oid, map[string]any{"useCommonEndpoint": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { idpTokenProjection(t, tc.provider, tc.extra, tc.sub, tc.social) })
	}
}
func idpTokenProjection(t *testing.T, provider string, extra map[string]any, sub string, social bool) {
	e := newUsersEnv(t)
	id := e.providerUser(t, provider, extra, sub)

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
	if ident["access_token"] != idpAccess || ident["refresh_token"] != idpRefresh || ident["isSocial"] != social || ident["provider"] != provider {
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
	if b, _ := json.Marshal(mgmt.UserJSON(&store.User{UserID: id, Identities: []store.Identity{{Provider: provider, UserID: sub}}})); strings.Contains(string(b), "access_token") {
		t.Fatal("generic user projection has token fields")
	}
	// A missing token record omits the fields rather than failing.
	_ = e.st.Federation().DeleteTokens(context.Background(), store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: "con_google", Subject: sub})
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
