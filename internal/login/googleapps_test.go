package login

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A google-apps connection signs in only accounts of its Workspace (the ID
// token's hd claim); the identity is the lowercase email.
func TestGoogleAppsLogin(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T, hd any) *socialEnv {
		s := newSocialEnv(t)
		s.google.extraClaims = map[string]any{"hd": hd}
		spec := connrules.Spec{Name: "workspace", Strategy: "google-apps", EnabledClients: []string{"spa"},
			Options: connrules.Options{Extra: map[string]any{"client_id": "client", "domain": "idp.example"}}}
		c := &store.Connection{TenantID: s.tenant.ID, ID: "con_ws", CreatedAt: fixedNow(), Origin: store.OriginAPI}
		connrules.Apply(&spec, c)
		sealed, err := federation.SealCredentials(s.h.Federation.Wrapper, s.tenant.ID, c.ID, federation.Credentials{ClientSecret: "provider-secret"})
		if err != nil {
			t.Fatal(err)
		}
		c.FederationSecretsSealed, c.FederationRevision = sealed, 1
		if err := s.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("member of the workspace", func(t *testing.T) {
		s := setup(t, "idp.example")
		toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.google, "workspace", "Ann"), "app.acme.test")
		u, err := s.st.Users().FindByIdentity(ctx, s.tenant.ID, "con_ws", "ann@idp.example")
		if err != nil || u.UserID != "google-apps|ann@idp.example" || u.Identities[0].Provider != "google-apps" {
			t.Fatalf("%+v %v", u, err)
		}
	})
	for name, hd := range map[string]any{"consumer account": nil, "other workspace": "other.example"} {
		t.Run(name, func(t *testing.T) {
			s := setup(t, hd)
			if hd == nil {
				s.google.extraClaims = nil
			}
			rec := s.explicitLogin(t, s.browser("acme.example.test"), s.google, "workspace", "Ann")
			if rec.Code == 302 {
				t.Fatalf("signed in: %s", rec.Header().Get("Location"))
			}
			if _, n, _ := s.st.Users().List(ctx, s.tenant.ID, &store.UserQuery{Op: store.QueryTerm, Field: "identities.provider", Kind: store.KindString, Value: "google-apps"}, store.UserSort{Field: "user_id"}, store.Page{}); n != 0 {
				t.Fatalf("%d users provisioned", n)
			}
		})
	}
}
