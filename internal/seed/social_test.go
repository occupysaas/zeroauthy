package seed

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const socialSeed = `
tenants:
  - name: acme
    domains: [acme.test]
    default_directory: Db
    clients:
      - {client_id: spa, name: SPA, app_type: spa, callbacks: ["https://app.acme.test/cb"]}
    connections:
      - {name: Db, enabled_clients: [spa]}
      - name: corp
        strategy: oidc
        enabled_clients: [spa]
        show_as_button: true
        options:
          type: back_channel
          client_id: corp-client
          client_secret: SECRET
          discovery_url: https://idp.example/.well-known/openid-configuration
          scopes: openid profile
`

func TestSeedSocialConnection(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	apply := func(doc string) error {
		t.Helper()
		f, err := Parse([]byte(doc))
		if err != nil {
			return err
		}
		return Apply(ctx, st, f, fixedNow, w)
	}
	get := func() *store.Connection {
		t.Helper()
		tn, err := st.Tenants().GetByName(ctx, "acme")
		if err != nil {
			t.Fatal(err)
		}
		c, err := st.Connections().GetByName(ctx, tn.ID, "corp")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if err := apply(strings.Replace(socialSeed, "SECRET", "first", 1)); err != nil {
		t.Fatal(err)
	}
	c := get()
	if c.FederationRevision != 1 || c.Extra["client_secret"] != nil {
		t.Fatalf("revision %d extra %v", c.FederationRevision, c.Extra)
	}
	creds, err := federation.OpenCredentials(w, c.TenantID, c.ID, c.FederationSecretsSealed)
	if err != nil || creds.ClientSecret != "first" {
		t.Fatalf("sealed %v", err)
	}
	// An unchanged re-apply is not a rotation.
	if err := apply(strings.Replace(socialSeed, "SECRET", "first", 1)); err != nil {
		t.Fatal(err)
	}
	if again := get(); again.FederationRevision != 1 || !bytes.Equal(again.FederationSecretsSealed, c.FederationSecretsSealed) {
		t.Fatalf("unchanged re-apply moved revision to %d", again.FederationRevision)
	}
	// The first discovery pins the issuer; re-applying keeps it.
	if _, err := federation.PinIssuer(ctx, st, c.TenantID, c.ID, 1, "https://idp.example"); err != nil {
		t.Fatal(err)
	}
	if err := apply(strings.Replace(socialSeed, "SECRET", "second", 1)); err != nil {
		t.Fatal(err)
	}
	rot := get()
	creds, _ = federation.OpenCredentials(w, rot.TenantID, rot.ID, rot.FederationSecretsSealed)
	if creds.ClientSecret != "second" || rot.FederationRevision != 3 {
		t.Fatalf("rotation revision %d", rot.FederationRevision)
	}
	if _, err := federation.PinIssuer(ctx, st, rot.TenantID, rot.ID, 3, "https://other.example"); err == nil {
		t.Fatal("re-apply unpinned the issuer")
	}
	// Immutable bindings hold for the seed too.
	if err := apply(strings.Replace(strings.Replace(socialSeed, "SECRET", "second", 1), "corp-client", "changed", 1)); err == nil {
		t.Fatal("seed changed the client binding")
	}
	for name, doc := range map[string]string{
		"no secret":     strings.Replace(socialSeed, "          client_secret: SECRET\n", "", 1),
		"db options":    strings.Replace(socialSeed, "{name: Db, enabled_clients: [spa]}", "{name: Db, enabled_clients: [spa], options: {x: 1}}", 1),
		"front channel": strings.Replace(socialSeed, "back_channel", "front_channel", 1),
	} {
		if err := apply(doc); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
