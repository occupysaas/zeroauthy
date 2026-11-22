package seed

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"strings"
	"testing"
)

func TestEnterpriseSeeds(t *testing.T) {
	for _, options := range []string{
		`{type: back_channel, client_id: client, client_secret: fixture, scope: openid, discovery_url: "https://idp.example/discovery"}`,
		`{type: front_channel, client_id: client, scope: openid, discovery_url: "https://idp.example/discovery"}`,
		`{type: back_channel, client_id: client, scope: openid, discovery_url: "https://idp.example/discovery", token_endpoint_auth_method: private_key_jwt}`,
	} {
		ctx := context.Background()
		s := memory.New()
		w := testWrapper(t)
		doc := "tenants: [{name: acme, connections: [{name: corp, strategy: oidc, options: " + options + "}]}]"
		f, e := Parse([]byte(doc))
		if e != nil {
			t.Fatal(e)
		}
		if e := Apply(ctx, s, f, fixedNow, w); e != nil {
			t.Fatal(e)
		}
		tn, e := s.Tenants().GetByName(ctx, "acme")
		if e != nil {
			t.Fatal(e)
		}
		c, e := s.Connections().GetByName(ctx, tn.ID, "corp")
		if e != nil {
			t.Fatal(e)
		}
		keys, e := s.ConnectionKeys().List(ctx, tn.ID, c.ID)
		if e != nil || len(keys) != 0 {
			t.Fatal("keys seeded", keys, e)
		}
		if e := Apply(ctx, s, f, fixedNow, w); e != nil {
			t.Fatal(e)
		}
		changed, e := Parse([]byte(strings.Replace(doc, "client_id: client", "client_id: changed", 1)))
		if e != nil {
			t.Fatal(e)
		}
		if e := Apply(ctx, s, changed, fixedNow, w); e == nil {
			t.Fatal("seed changed immutable client binding")
		}
	}
}
func TestOktaSeed(t *testing.T) {
	doc := `tenants: [{name: acme, connections: [{name: workforce, strategy: okta, options: {domain: DEV-1.OKTA.COM, client_id: client, client_secret: fixture, scope: openid}}]}]`
	f, e := Parse([]byte(doc))
	if e != nil {
		t.Fatal(e)
	}
	if e := Apply(context.Background(), memory.New(), f, fixedNow, testWrapper(t)); e != nil {
		t.Fatal(e)
	}
	if _, e := Parse([]byte(strings.Replace(doc, "DEV-1.OKTA.COM", "https://dev-1.okta.com", 1))); e == nil {
		t.Fatal("invalid domain accepted")
	}
}

func TestSeedChannelSwitchClearsSecret(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	w := testWrapper(t)
	back := `tenants: [{name: acme, connections: [{name: corp, strategy: oidc, options: {type: back_channel, client_id: client, client_secret: fixture, scope: openid, discovery_url: "https://idp.example/discovery"}}]}]`
	f, e := Parse([]byte(back))
	if e != nil {
		t.Fatal(e)
	}
	if e := Apply(ctx, s, f, fixedNow, w); e != nil {
		t.Fatal(e)
	}
	front := strings.Replace(strings.Replace(back, "back_channel", "front_channel", 1), "client_secret: fixture, ", "", 1)
	f, e = Parse([]byte(front))
	if e != nil {
		t.Fatal(e)
	}
	if e := Apply(ctx, s, f, fixedNow, w); e != nil {
		t.Fatal(e)
	}
	tn, _ := s.Tenants().GetByName(ctx, "acme")
	c, e := s.Connections().GetByName(ctx, tn.ID, "corp")
	if e != nil || len(c.FederationSecretsSealed) != 0 {
		t.Fatal("unused front-channel secret retained", e)
	}
}

type noEnterpriseKeys struct{ store.Store }

func (noEnterpriseKeys) ConnectionKeysSupported() bool { return false }
func TestEnterpriseSeedUnavailable(t *testing.T) {
	doc := `tenants: [{name: acme, connections: [{name: corp, strategy: oidc, options: {type: back_channel, client_id: client, scope: openid, discovery_url: "https://idp.example/discovery", token_endpoint_auth_method: private_key_jwt}}]}]`
	f, e := Parse([]byte(doc))
	if e != nil {
		t.Fatal(e)
	}
	if e := Apply(context.Background(), noEnterpriseKeys{memory.New()}, f, fixedNow, testWrapper(t)); !errors.Is(e, store.ErrConnectionKeysUnavailable) {
		t.Fatal("missing capability accepted", e)
	}
}
