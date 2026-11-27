package mgmt_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestOAuth1TokenSecretProjection: an OAuth 1.0a identity's token secret is
// returned as identities[].access_token_secret exactly where its access token
// is (Plan 39b), and nowhere else.
func TestOAuth1TokenSecretProjection(t *testing.T) {
	const secret = "upstream-token-secret-CCC"
	e := newUsersEnv(t)
	ctx := context.Background()
	if err := e.st.Connections().Create(ctx, &store.Connection{TenantID: e.tn.ID, ID: "con_o1", Name: "o1", Strategy: "oauth1", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	id := store.FederatedPublicID("oauth1", "o1", "783214")
	if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: id, Identities: []store.Identity{{Connection: "o1", Provider: "oauth1", UserID: "o1|783214"}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	key := store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: "con_o1", Subject: "783214"}
	sealed, _ := federation.SealTokens(e.w, key, federation.TokenSet{AccessToken: idpAccess, TokenSecret: secret, TokenType: "oauth1"})
	if err := e.st.Federation().PutTokens(ctx, key, sealed); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := e.getUser(t, m2mCaller("read:users"), id); code != 200 || strings.Contains(body, secret) {
		t.Fatalf("no token scope: %d %s", code, body)
	}
	code, body, _ := e.getUser(t, m2mCaller("read:users", "read:user_idp_tokens"), id)
	var u map[string]any
	_ = json.Unmarshal([]byte(body), &u)
	ident := u["identities"].([]any)[0].(map[string]any)
	if code != 200 || ident["access_token"] != idpAccess || ident["access_token_secret"] != secret || ident["isSocial"] != true {
		t.Fatalf("identity %d %v", code, ident)
	}
	if code, body, _ := e.getUser(t, mgmt.Caller{Kind: mgmt.Operator, UserID: "op"}, id); code != 200 || strings.Contains(body, secret) {
		t.Fatalf("operator: %d %s", code, body)
	}
}
