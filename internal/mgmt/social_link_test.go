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
func TestSocialLinkUnlink(t *testing.T) { socialLinkUnlink(t, "google-oauth2", nil, "G1", true) }
func TestMicrosoftLinkUnlink(t *testing.T) {
	const tid = "11111111-2222-3333-4444-555555555555"
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	for _, tc := range []struct {
		name, provider, sub string
		extra               map[string]any
		social              bool
	}{
		{"personal", "windowslive", "Case|Sensitive", nil, true},
		{"single", "waad", oid, map[string]any{"tenant_domain": tid}, false},
		{"multi", "waad", tid + ":" + oid, map[string]any{"useCommonEndpoint": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { socialLinkUnlink(t, tc.provider, tc.extra, tc.sub, tc.social) })
	}
}
func socialLinkUnlink(t *testing.T, provider string, extra map[string]any, sub string, social bool) {
	e := newUsersEnv(t)
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
	key := store.FederatedIdentityKey{TenantID: e.tn.ID, ConnectionID: g.ID, Subject: sub}
	if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: publicID, Email: "g@x.test", EmailVerified: true,
		Identities: []store.Identity{{Connection: g.Name, Provider: provider, UserID: identityID}}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Federation().PutTokens(ctx, key, []byte("sealed-tokens")); err != nil {
		t.Fatal(err)
	}
	p := e.mustCreate(t, map[string]any{"email": "primary@x.test", "password": "primary pass 1"})["user_id"].(string)
	epoch0, _ := e.st.Federation().IdentityEpoch(ctx, e.tn.ID)

	rec, out := e.link(t, p, map[string]any{"provider": provider, "user_id": identityID})
	if rec.Code != 201 {
		t.Fatalf("link = %d %s", rec.Code, rec.Body)
	}
	ids := listUsers(t, out)
	if len(ids) != 2 || ids[1]["isSocial"] != social || ids[1]["provider"] != provider || ids[0]["isSocial"] != false {
		t.Fatalf("identities %v", ids)
	}
	owner, err := e.st.Users().FindByIdentity(ctx, e.tn.ID, g.ID, sub)
	if err != nil || owner.UserID != p {
		t.Fatalf("owner after link %v %v", owner, err)
	}
	if b, err := e.st.Federation().GetTokens(ctx, key); err != nil || string(b) != "sealed-tokens" {
		t.Fatalf("tokens after link %q %v", b, err)
	}
	if epoch, _ := e.st.Federation().IdentityEpoch(ctx, e.tn.ID); epoch <= epoch0 {
		t.Fatal("link did not move the identity epoch")
	}

	if rec, _ := e.unlink(t, p, provider, identityID); rec.Code != 200 {
		t.Fatalf("unlink = %d %s", rec.Code, rec.Body)
	}
	owner, err = e.st.Users().FindByIdentity(ctx, e.tn.ID, g.ID, sub)
	if err != nil || owner.UserID != publicID {
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
		u, err = svc.ResolveIdentity(ctx, tx, g, federation.ProviderResult{Profile: federation.Profile{Subject: sub}, Tokens: federation.TokenSet{AccessToken: "a", TokenType: "Bearer"}})
		return err
	}); err != nil || u.UserID != publicID {
		t.Fatalf("recreated login %v %v", u, err)
	}
	if err := e.st.Users().Delete(ctx, e.tn.ID, publicID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Federation().GetTokens(ctx, key); err == nil {
		t.Fatal("tokens survive user deletion")
	}
	if _, err := e.st.Users().FindByIdentity(ctx, e.tn.ID, g.ID, sub); err == nil {
		t.Fatal("index survives user deletion")
	}
}
