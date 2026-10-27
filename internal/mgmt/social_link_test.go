package mgmt_test

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Plan 24: linking and unlinking a social identity moves index ownership;
// the sealed token record stays with the identity.
func TestSocialLinkUnlink(t *testing.T) {
	e := newUsersEnv(t)
	ctx := context.Background()
	g := &store.Connection{TenantID: e.tn.ID, ID: "con_google", Name: "google-oauth2", Strategy: "google-oauth2", CreatedAt: now}
	if err := e.st.Connections().Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	key := store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: g.ID, Subject: "G1"}
	if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: "google-oauth2|G1", Email: "g@x.test", EmailVerified: true,
		Identities: []store.Identity{{Connection: g.Name, Provider: "google-oauth2", UserID: "G1"}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Federation().PutTokens(ctx, key, []byte("sealed-tokens")); err != nil {
		t.Fatal(err)
	}
	p := e.mustCreate(t, map[string]any{"email": "primary@x.test", "password": "primary pass 1"})["user_id"].(string)
	epoch0, _ := e.st.Federation().IdentityEpoch(ctx, e.tn.ID)

	rec, out := e.link(t, p, map[string]any{"provider": "google-oauth2", "user_id": "G1"})
	if rec.Code != 201 {
		t.Fatalf("link = %d %s", rec.Code, rec.Body)
	}
	ids := listUsers(t, out)
	if len(ids) != 2 || ids[1]["isSocial"] != true || ids[0]["isSocial"] != false {
		t.Fatalf("identities %v", ids)
	}
	owner, err := e.st.Users().FindByIdentity(ctx, e.tn.ID, g.ID, "G1")
	if err != nil || owner.UserID != p {
		t.Fatalf("owner after link %v %v", owner, err)
	}
	if b, err := e.st.Federation().GetTokens(ctx, key); err != nil || string(b) != "sealed-tokens" {
		t.Fatalf("tokens after link %q %v", b, err)
	}
	if epoch, _ := e.st.Federation().IdentityEpoch(ctx, e.tn.ID); epoch <= epoch0 {
		t.Fatal("link did not move the identity epoch")
	}

	if rec, _ := e.unlink(t, p, "google-oauth2", "G1"); rec.Code != 200 {
		t.Fatalf("unlink = %d %s", rec.Code, rec.Body)
	}
	owner, err = e.st.Users().FindByIdentity(ctx, e.tn.ID, g.ID, "G1")
	if err != nil || owner.UserID != "google-oauth2|G1" {
		t.Fatalf("owner after unlink %v %v", owner, err)
	}
	if b, _ := e.st.Federation().GetTokens(ctx, key); string(b) != "sealed-tokens" {
		t.Fatal("tokens lost on unlink")
	}

	// The recreated user logs in by its identity; deleting it cleans up.
	svc := &federation.Service{Wrapper: e.w, Now: func() time.Time { return now }}
	var u *store.User
	if err := e.st.WithTx(ctx, func(tx store.Store) error {
		var err error
		u, err = svc.ResolveIdentity(ctx, tx, g, federation.ProviderResult{Profile: federation.Profile{Subject: "G1"}, Tokens: federation.TokenSet{AccessToken: "a", TokenType: "Bearer"}})
		return err
	}); err != nil || u.UserID != "google-oauth2|G1" {
		t.Fatalf("recreated login %v %v", u, err)
	}
	if err := e.st.Users().Delete(ctx, e.tn.ID, "google-oauth2|G1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Federation().GetTokens(ctx, key); err == nil {
		t.Fatal("tokens survive user deletion")
	}
	if _, err := e.st.Users().FindByIdentity(ctx, e.tn.ID, g.ID, "G1"); err == nil {
		t.Fatal("index survives user deletion")
	}
}
