package seed

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSeedCanonicalAndDomainOwnership(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	apply := func(raw, base string) error {
		f, err := Parse([]byte(raw))
		if err != nil {
			return err
		}
		if err = f.CheckManagementAPI(base); err != nil {
			return err
		}
		return Apply(ctx, st, f, fixedNow, testWrapper(t))
	}
	if err := apply("tenants: [{name: acme, domains: [first.example.test, second.example.test]}]", ""); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.CanonicalHost != "first.example.test" {
		t.Fatalf("new canonical=%q", tn.CanonicalHost)
	}
	d := &store.CustomDomain{TenantID: tn.ID, ID: "pending", Domain: "pending.example.test", Generation: 1}
	if err := st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: tn.ID, DomainID: d.ID, Generation: 1, Kind: store.HostPublic}); err != nil {
		t.Fatal(err)
	}
	if err := apply("tenants: [{name: acme, friendly_name: Updated}]", ""); err != nil {
		t.Fatal(err)
	}
	if h, err := st.CustomDomains().GetHost(ctx, d.Domain); err != nil || h.Active || h.DomainID != "pending" {
		t.Fatalf("omitted domains changed public claim=%+v,%v", h, err)
	}
	if err := apply("tenants: [{name: acme, domains: [second.example.test, first.example.test]}]", ""); err != nil {
		t.Fatal(err)
	}
	apis, _ := st.ResourceServers().List(ctx, tn.ID)
	if len(apis) != 1 || apis[0].Identifier != "https://first.example.test/api/v2/" {
		t.Fatalf("reorder rotated audience: %+v", apis)
	}
	if err := apply("tenants: [{name: acme, domains: [second.example.test]}]", ""); err == nil {
		t.Fatal("canonical removal accepted")
	}
}
func TestSeedDomainApplyPreservesPublicRows(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := Parse([]byte("tenants: [{name: acme, domains: [old.example.test]}]"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.CheckManagementAPI("auth.example.test"); err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	d := &store.CustomDomain{TenantID: tn.ID, ID: "ready", Domain: "ready.example.test", Generation: 1}
	if err = st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err = st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: tn.ID, DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	f.Tenants[0].Domains = []string{"new.example.test"}
	if err = Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	if h, err := st.CustomDomains().GetHost(ctx, d.Domain); err != nil || !h.Active || h.DomainID != "ready" {
		t.Fatalf("explicit domains changed public=%+v,%v", h, err)
	}
	if _, err = st.CustomDomains().GetHost(ctx, "old.example.test"); err == nil {
		t.Fatal("old operator alias retained")
	}
	f.Mode = ModeCreateOnly
	f.Tenants[0].Domains = []string{"ignored.example.test"}
	if err = Apply(ctx, st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	if _, err = st.CustomDomains().GetHost(ctx, "ignored.example.test"); err == nil {
		t.Fatal("create-only replaced domains")
	}
}
func TestSeedDoesNotMaskAudienceDrift(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "acme", Domains: []string{"old.example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: "a", ID: "old", Identifier: "https://old.example.test/api/v2/", IsSystem: true}); err != nil {
		t.Fatal(err)
	}
	f, err := Parse([]byte("tenants: [{name: acme, domains: [new.example.test]}]"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.CheckManagementAPI("auth.example.test"); err != nil {
		t.Fatal(err)
	}
	err = Apply(ctx, st, f, fixedNow, testWrapper(t))
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("drift masked: %v", err)
	}
	rows, _ := st.ResourceServers().List(ctx, "a")
	if len(rows) != 1 {
		t.Fatal("drift repair created another audience")
	}
}
