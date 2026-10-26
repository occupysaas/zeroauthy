package email

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Email templates get the link's public custom domain (name and metadata),
// never origin aliases, proofs, keys or certificates; canonical links get none.
func TestPublicCustomDomainEmailContext(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t1", Name: "acme", CanonicalHost: "acme.auth.example.test"}); err != nil {
		t.Fatal(err)
	}
	d := &store.CustomDomain{TenantID: "t1", ID: "cd_1", Domain: "id.acme.test", OriginHost: "cd-01.auth.example.test", Generation: 1,
		Status: customdomain.StatusReady, Lifecycle: customdomain.LifecycleActive, ProxyKeyHash: []byte("secret-hash"), ProofRecordValue: "proof",
		DomainMetadata: map[string]string{"brand": "Acme"}}
	if err := st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: "t1", DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st}
	vars, err := s.renderContext(ctx, "t1", nil, nil, nil, "en", "https://id.acme.test/u/reset-verify?ticket=x")
	if err != nil {
		t.Fatal(err)
	}
	cd, _ := vars["custom_domain"].(map[string]any)
	md, _ := cd["domain_metadata"].(map[string]any)
	if cd["domain"] != "id.acme.test" || md["brand"] != "Acme" || len(cd) != 2 {
		t.Fatalf("custom_domain = %#v", vars["custom_domain"])
	}
	vars, err = s.renderContext(ctx, "t1", nil, nil, nil, "en", "https://acme.auth.example.test/u/reset-verify?ticket=x")
	if err != nil || vars["custom_domain"] != nil {
		t.Fatalf("canonical = %#v, %v", vars["custom_domain"], err)
	}
}
