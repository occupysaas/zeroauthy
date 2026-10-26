package seed

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/hostedlogin"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSeedHostedLoginOwnership(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	first, _ := Parse([]byte("tenants:\n  - name: acme\n    branding: {logo_url: https://example.test/one.svg}\n"))
	if err := Apply(ctx, st, first, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	svc := hostedlogin.Service{Store: st}
	c, err := svc.Load(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Prompts = map[string]any{"identifier_first": true}
	if err := st.HostedLogins().Put(ctx, c, c.Revision); err != nil {
		t.Fatal(err)
	}
	second, _ := Parse([]byte("tenants:\n  - name: acme\n    branding: {logo_url: https://example.test/two.svg}\n"))
	if err := Apply(ctx, st, second, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	c, err = svc.Load(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Branding["logo_url"] != "https://example.test/two.svg" {
		t.Fatalf("seed branding was not projected: %v", c.Branding)
	}
	if c.Prompts["identifier_first"] != true {
		t.Fatal("unrelated API prompt setting overwritten")
	}
	omitted, _ := Parse([]byte("tenants:\n  - name: acme\n    friendly_name: Acme\n"))
	if err := Apply(ctx, st, omitted, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	c, err = svc.Load(ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Branding["logo_url"] != "https://example.test/two.svg" {
		t.Fatal("omitted branding overwritten")
	}
}
