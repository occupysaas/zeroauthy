package hostedlogin

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestLegacyHostedConfigMigratesOnce(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	tenant := &store.Tenant{ID: "t1", Name: "acme", Branding: store.Branding{LogoURL: "https://example.test/old.svg"}, CustomText: store.CustomText{"login": {"en": {"login": {"title": "Old"}}}}}
	if err := st.Tenants().Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	svc := Service{Store: st}
	first, err := svc.Load(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Branding["logo_url"] != "https://example.test/old.svg" {
		t.Fatalf("migration lost branding: %#v", first)
	}
	first.Branding["logo_url"] = "https://example.test/new.svg"
	if err := st.HostedLogins().Put(ctx, first, first.Revision); err != nil {
		t.Fatal(err)
	}
	old, err := st.Tenants().Get(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	old.Branding.LogoURL = "https://example.test/stale.svg"
	if err := st.Tenants().Update(ctx, old); err != nil {
		t.Fatal(err)
	}
	second, err := svc.Load(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if second.Branding["logo_url"] != "https://example.test/new.svg" {
		t.Fatalf("legacy overwrote canonical branding: %#v", second)
	}
}
