package tenantsetup_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

func TestCanonicalDomainUpgrade(t *testing.T) {
	for _, tc := range []struct{ base, canonical, audience string }{
		{"auth.example.test", "acme.auth.example.test", "https://acme.auth.example.test/api/v2/"},
		{"", "localhost:8443", "https://localhost:8443/api/v2/"},
	} {
		t.Run(tc.canonical, func(t *testing.T) {
			ctx := context.Background()
			st := memory.New()
			original := []string{"localhost:8443", "second.example.test"}
			must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "acme", Name: "acme", Domains: original}))
			must(t, st.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: "acme", ID: "api", Identifier: tc.audience, IsSystem: true}))
			must(t, st.ClientGrants().Create(ctx, &store.ClientGrant{TenantID: "acme", ID: "grant", ClientID: "client", Audience: tc.audience, Scopes: []string{"read:users"}}))
			must(t, tenantsetup.ReconcileDomains(ctx, st, tc.base, "admin.example.test", "origin.example.test"))
			got, err := st.Tenants().Get(ctx, "acme")
			must(t, err)
			if got.CanonicalHost != tc.canonical || !slices.Equal(got.Domains[:len(original)], original) {
				t.Fatalf("tenant = %+v", got)
			}
			if id := tenant.ManagementAPIIdentifier(got, "changed.example.test"); id != tc.audience {
				t.Fatalf("audience rotated: %s", id)
			}
			grant, err := st.ClientGrants().Find(ctx, "acme", "client", tc.audience, "client")
			must(t, err)
			if grant.Audience != tc.audience || !slices.Equal(grant.Scopes, []string{"read:users"}) {
				t.Fatalf("grant changed: %+v", grant)
			}
			binding, err := st.CustomDomains().GetHost(ctx, tc.canonical)
			must(t, err)
			if binding.Kind != store.HostCanonical || !binding.Active || binding.TenantID != "acme" {
				t.Fatalf("claim = %+v", binding)
			}
		})
	}
}

func TestDomainMigrationRestart(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a", Domains: []string{"a.example.test"}}))
	must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "b", Name: "b", Domains: []string{"b.example.test"}}))
	must(t, st.ResourceServers().Create(ctx, &store.ResourceServer{TenantID: "b", ID: "api", Identifier: "https://wrong.example.test/api/v2/", IsSystem: true}))
	err := tenantsetup.ReconcileDomains(ctx, st, "", "admin.example.test", "")
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("drift = %v", err)
	}
	a, _ := st.Tenants().Get(ctx, "a")
	if a.CanonicalHost != "" {
		t.Fatal("failed migration partially committed")
	}
	must(t, st.ResourceServers().Delete(ctx, "b", "api"))
	must(t, tenantsetup.ReconcileDomains(ctx, st, "", "admin.example.test", ""))
	before, _ := st.Tenants().Get(ctx, "a")
	must(t, tenantsetup.ReconcileDomains(ctx, st, "", "admin.example.test", ""))
	after, _ := st.Tenants().Get(ctx, "a")
	if before.CanonicalHost != after.CanonicalHost || !slices.Equal(before.Domains, after.Domains) {
		t.Fatal("restart changed identity")
	}
	if err := tenantsetup.ReconcileDomains(ctx, st, "changed.example.test", "admin.example.test", ""); err == nil {
		t.Fatal("base drift accepted")
	}
}

func TestDomainMigrationReservedHosts(t *testing.T) {
	for _, domains := range [][]string{{"admin.example.test"}, {"b.auth.example.test"}, {"system.auth.example.test"}} {
		t.Run(domains[0], func(t *testing.T) {
			ctx := context.Background()
			st := memory.New()
			must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a", Domains: domains}))
			must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "b", Name: "b"}))
			if err := tenantsetup.ReconcileDomains(ctx, st, "auth.example.test", "admin.example.test", ""); err == nil {
				t.Fatal("reserved overlap accepted")
			}
			a, _ := st.Tenants().Get(ctx, "a")
			if a.CanonicalHost != "" {
				t.Fatal("overlap partially initialized")
			}
		})
	}
}

// A tenant with no host keeps no identity until an operator gives it one.
func TestDomainMigrationHostlessTenant(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	must(t, st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a"}))
	must(t, tenantsetup.ReconcileDomains(ctx, st, "", "admin.example.test", ""))
	a, _ := st.Tenants().Get(ctx, "a")
	if a.CanonicalHost != "" || len(a.Domains) != 0 {
		t.Fatalf("hostless tenant = %+v", a)
	}
}

type oldDomainStore struct{ store.Store }

func (oldDomainStore) CustomDomains() store.CustomDomains { return store.UnimplementedCustomDomains{} }
func TestDomainMigrationRequiresCapability(t *testing.T) {
	err := tenantsetup.ReconcileDomains(context.Background(), oldDomainStore{memory.New()}, "auth.example.test", "admin.example.test", "")
	if !errors.Is(err, store.ErrCustomDomainRepositoryUnavailable) {
		t.Fatalf("capability error = %v", err)
	}
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
