package seed

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const descriptorSeed = `
tenants:
 - name: acme
   domains: [acme.test]
   connections:
    - name: facebook
      strategy: facebook
      options:
       client_id: fb-app
       client_secret: fb-throwaway-secret
       email: true
       OPTEXTRA
    - name: x
      strategy: twitter
      options:
       client_id: x-client
       client_secret: x-throwaway-secret
       protocol: oauth1
`

// TestSeedDescriptorSocial seeds Plan 39b strategies through the shared rules:
// the effective scope is stored, and the rules' refusals apply.
func TestSeedDescriptorSocial(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(strings.Replace(descriptorSeed, "OPTEXTRA", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	c, err := st.Connections().GetByName(ctx, tn.ID, "facebook")
	if err != nil {
		t.Fatal(err)
	}
	if c.Extra["scope"] != "public_profile,email" || len(c.FederationSecretsSealed) == 0 {
		t.Fatalf("facebook scope %v sealed %d", c.Extra["scope"], len(c.FederationSecretsSealed))
	}
	if x, err := st.Connections().GetByName(ctx, tn.ID, "x"); err != nil || x.Extra["protocol"] != "oauth1" {
		t.Fatalf("twitter %+v %v", x, err)
	}
	for _, extra := range []string{"tokenURL: https://evil.example/token", "scope: [email]", "email: maybe"} {
		if _, err := Parse([]byte(strings.Replace(descriptorSeed, "OPTEXTRA", extra, 1))); err == nil {
			t.Fatalf("%q accepted", extra)
		}
	}
}

const tier2Seed = `
tenants:
 - name: acme
   domains: [acme.test]
   connections:
    - name: wordpress
      strategy: wordpress
      options: {client_id: wp, client_secret: wp-throwaway-secret, scope: [global]}
    - name: exact
      strategy: exact
      options: {client_id: ex, client_secret: ex-throwaway-secret, baseUrl: "https://start.exactonline.nl"}
    - name: fitbit
      strategy: fitbit
      options: {client_id: fb, client_secret: fb-throwaway-secret}
    - name: evernote
      strategy: evernote
      options: {client_id: en, client_secret: en-throwaway-secret}
`

// TestSeedTier2 seeds Plan 39d strategies, the retired Fitbit included.
func TestSeedTier2(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte(tier2Seed))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	for _, name := range []string{"wordpress", "exact", "fitbit", "evernote"} {
		if c, err := st.Connections().GetByName(ctx, tn.ID, name); err != nil || len(c.FederationSecretsSealed) == 0 {
			t.Fatalf("%s: %+v %v", name, c, err)
		}
	}
	if _, err := Parse([]byte(strings.Replace(tier2Seed, `baseUrl: "https://start.exactonline.nl"`, `baseUrl: "https://evil.example"`, 1))); err == nil {
		t.Fatal("bad Exact baseUrl accepted")
	}
}
