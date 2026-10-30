package orglogin

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestOrganizationDiscoveryNormalization(t *testing.T) {
	for _, in := range []string{"*.example.com", "127.0.0.1", "https://example.com", "example.com:443", "example.com.", "-bad.com", "a..com", "foo", " x.com"} {
		if got, err := NormalizeDiscoveryDomain(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	for in, want := range map[string]string{"EXAMPLE.COM": "example.com", "BÜCHER.de": "xn--bcher-kva.de"} {
		if got, err := NormalizeDiscoveryDomain(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

func TestOrganizationDiscoveryPolicy(t *testing.T) {
	st, o, c := entitlementFixture(t)
	ctx := context.Background()
	conn := &store.Connection{TenantID: "t", ID: "con_0000000000000001", Name: "db", Strategy: "auth0", EnabledClients: []string{c.ClientID}}
	if err := st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if err := st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: "t", OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}, true); err != nil {
		t.Fatal(err)
	}
	domain := &store.OrganizationDiscoveryDomain{TenantID: "t", OrganizationID: o.ID, ID: "domain", Domain: "example.com", Status: "pending", UseForOrganizationDiscovery: true}
	if err := st.OrganizationsII().PutDiscoveryDomain(ctx, domain, true); err != nil {
		t.Fatal(err)
	}
	check := func(email string, want int) {
		t.Helper()
		got, err := Discover(ctx, st, "t", c.ClientID, email)
		if err != nil || len(got) != want {
			t.Fatalf("%s: %v %v want %d", email, got, err, want)
		}
	}
	check("user@example.com", 0)
	domain.Status = "verified"
	if err := st.OrganizationsII().PutDiscoveryDomain(ctx, domain, false); err != nil {
		t.Fatal(err)
	}
	check("user@EXAMPLE.COM", 1)
	check("user@sub.example.com", 0)
	domain.UseForOrganizationDiscovery = false
	if err := st.OrganizationsII().PutDiscoveryDomain(ctx, domain, false); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 0)
	domain.UseForOrganizationDiscovery = true
	if err := st.OrganizationsII().PutDiscoveryDomain(ctx, domain, false); err != nil {
		t.Fatal(err)
	}
	o.IsAppEntitlementActive = true
	if err := st.Organizations().Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 0)
	if err := st.OrganizationsII().PutClients(ctx, "t", o.ID, []store.OrganizationClient{{ClientID: c.ClientID, UseForMemberAccess: true}}); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 1)
	for i := 0; i < 25; i++ {
		x := *o
		x.ID = fmt.Sprintf("org_%016d", i+2)
		x.Name = fmt.Sprintf("discovery%d", i)
		if err := st.Organizations().Create(ctx, &x, []store.OrganizationConnection{{ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
			t.Fatal(err)
		}
		d := *domain
		d.OrganizationID = x.ID
		if err := st.OrganizationsII().PutDiscoveryDomain(ctx, &d, true); err != nil {
			t.Fatal(err)
		}
		if err := st.OrganizationsII().PutClients(ctx, "t", x.ID, []store.OrganizationClient{{ClientID: c.ClientID, UseForMemberAccess: true}}); err != nil {
			t.Fatal(err)
		}
	}
	check("u@example.com", 26)
	got, err := Discover(ctx, st, "t", c.ClientID, "u@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].ID >= got[i].ID {
			t.Fatal("not sorted")
		}
	}
	link, err := st.Organizations().GetConnection(ctx, "t", o.ID, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	link.IsEnabledSet, link.IsEnabled = true, false
	if err := st.Organizations().PutConnection(ctx, *link, false); err != nil {
		t.Fatal(err)
	}
	check("u@example.com", 25)
	link.IsEnabled = true
	if err := st.Organizations().PutConnection(ctx, *link, false); err != nil {
		t.Fatal(err)
	}
	c.IsFirstParty = false
	if err := st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 0)
	o.ThirdPartyClientAccess = "allow"
	if err := st.Organizations().Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 0)
	conn.IsDomainConnection = true
	if err := st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 1)
	c.OrganizationUsage = store.OrgUsageDeny
	if err := st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	check("user@example.com", 0)
	for _, email := range []string{"Name <u@example.com>", "u@@example.com", "u@127.0.0.1", "u@example.com.", "@example.com"} {
		if _, err := Discover(ctx, st, "t", c.ClientID, email); err == nil {
			t.Errorf("accepted %q", email)
		}
	}
	members, err := st.Organizations().Members(ctx, "t", o.ID, store.OrgPage{PerPage: 100})
	if err != nil || len(members.Items) != 0 {
		t.Fatalf("discovery enrolled members: %v %v", members, err)
	}
	legacy := entitlementLegacyStore{st}
	if _, err := Discover(ctx, legacy, "t", c.ClientID, "u@example.com"); !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
		t.Fatal(err)
	}
}

func TestOrganizationDiscoveryTenantIsolation(t *testing.T) {
	st, o, c := entitlementFixture(t)
	ctx := context.Background()
	for _, tid := range []string{"t", "other"} {
		if tid != "t" {
			if err := st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}); err != nil {
				t.Fatal(err)
			}
			x := *o
			x.TenantID = tid
			if err := st.Organizations().Create(ctx, &x, nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Connections().Create(ctx, &store.Connection{TenantID: tid, ID: "con_0000000000000001", Name: "db", Strategy: "auth0", EnabledClients: []string{c.ClientID}}); err != nil {
			t.Fatal(err)
		}
		if err := st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: tid, OrganizationID: o.ID, ConnectionID: "con_0000000000000001", ShowAsButton: true}, true); err != nil {
			t.Fatal(err)
		}
		if err := st.OrganizationsII().PutDiscoveryDomain(ctx, &store.OrganizationDiscoveryDomain{TenantID: tid, OrganizationID: o.ID, ID: "d", Domain: "xn--bcher-kva.de", Status: "verified", UseForOrganizationDiscovery: true}, true); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Discover(ctx, st, "t", c.ClientID, "u@BÜCHER.de")
	if err != nil || len(got) != 1 || got[0].TenantID != "t" {
		t.Fatalf("%v %v", got, err)
	}
	got, err = Discover(ctx, st, "t", c.ClientID, "u@sub.bücher.de")
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}
