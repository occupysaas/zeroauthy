package seed

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const organizationsIISeed = `
tenants:
- name: acme
  clients: [{name: Browser, client_id: browser, app_type: spa, token_endpoint_auth_method: none}]
  connections: [{name: Db}]
  organizations:
  - name: example
    is_app_entitlement_active: true
    third_party_client_access: allow
    clients: [{client_id: Browser, use_for_member_access: true}]
    connections: [{name: Db, is_enabled: false, organization_connection_name: Local, organization_access_level: none, organization_member_access_level: limited}]
    discovery_domains: [{domain: example.test, use_for_organization_discovery: true}]
`

func TestOrganizationsIISeedCreateOnly(t *testing.T) {
	st := memory.New()
	ctx := t.Context()
	w := testWrapper(t)
	apply := func(doc string) error {
		f, e := Parse([]byte(doc))
		if e != nil {
			return e
		}
		return Apply(ctx, st, f, fixedNow, w)
	}
	if e := apply(organizationsIISeed); e != nil {
		t.Fatal(e)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	org, e := st.Organizations().GetByName(ctx, tn.ID, "example")
	if e != nil {
		t.Fatal(e)
	}
	if !org.IsAppEntitlementActive || org.ThirdPartyClientAccess != "allow" {
		t.Fatalf("lost policy: %+v", org)
	}
	cs, e := st.OrganizationsII().ListClients(ctx, tn.ID, org.ID, store.OrgPage{})
	if e != nil || len(cs.Items) != 1 || cs.Items[0].ClientID != "browser" || !cs.Items[0].UseForMemberAccess {
		t.Fatalf("clients: %+v %v", cs, e)
	}
	ds, e := st.OrganizationsII().ListDiscoveryDomains(ctx, tn.ID, org.ID, store.OrgPage{})
	if e != nil || len(ds.Items) != 1 || ds.Items[0].Status != "pending" {
		t.Fatalf("domains: %+v %v", ds, e)
	}
	links, e := st.Organizations().Connections(ctx, tn.ID, org.ID, store.OrgPage{})
	if e != nil || len(links.Items) != 1 || links.Items[0].IsEnabled || links.Items[0].ConnectionName != "Local" {
		t.Fatalf("links: %+v %v", links, e)
	}
	org.IsAppEntitlementActive = false
	org.ThirdPartyClientAccess = "block"
	if e := st.Organizations().Update(ctx, org); e != nil {
		t.Fatal(e)
	}
	if e := st.OrganizationsII().DeleteClients(ctx, tn.ID, org.ID, []string{"browser"}); e != nil {
		t.Fatal(e)
	}
	if e := st.OrganizationsII().DeleteDiscoveryDomain(ctx, tn.ID, org.ID, ds.Items[0].ID); e != nil {
		t.Fatal(e)
	}
	if e := apply(organizationsIISeed); e != nil {
		t.Fatal(e)
	}
	org, _ = st.Organizations().GetByName(ctx, tn.ID, "example")
	cs, _ = st.OrganizationsII().ListClients(ctx, tn.ID, org.ID, store.OrgPage{})
	ds, _ = st.OrganizationsII().ListDiscoveryDomains(ctx, tn.ID, org.ID, store.OrgPage{})
	if org.IsAppEntitlementActive || org.ThirdPartyClientAccess != "block" || len(cs.Items) != 0 || len(ds.Items) != 0 {
		t.Fatal("reseed restored API-managed policy")
	}
	for _, bad := range []string{
		strings.Replace(organizationsIISeed, "client_id: Browser", "client_id: missing", 1),
		strings.Replace(organizationsIISeed, "name: Db, is_enabled", "name: missing, is_enabled", 1),
		strings.Replace(organizationsIISeed, "domain: example.test", "domain: example.test, status: verified", 1),
	} {
		fresh := memory.New()
		f, e := Parse([]byte(bad))
		if e == nil {
			e = Apply(ctx, fresh, f, fixedNow, w)
		}
		if e == nil {
			t.Fatal("invalid reference/attestation accepted")
		}
		if _, e = fresh.Tenants().GetByName(ctx, "acme"); e == nil {
			t.Fatal("invalid batch partially wrote tenant")
		}
	}
	for _, field := range []string{"invitations: []", "receipts: []", "ticket_id: secret", "invitation_url: secret"} {
		if _, e := Parse([]byte(strings.Replace(organizationsIISeed, "    is_app_entitlement_active: true", "    "+field, 1))); e == nil {
			t.Fatalf("accepted %s", field)
		}
	}
}

func TestOrganizationsIISeedCreateOnlyGrantPolicy(t *testing.T) {
	doc := strings.Replace(organizationsIISeed, "  connections: [{name: Db}]", `  resource_servers: [{name: API, identifier: 'https://api.test', scopes: [{value: read}]}]
  client_grants: [{client_id: browser, audience: 'https://api.test', scopes: [read], organization_usage: require, allow_any_organization: false}]
  connections: [{name: Db}]`, 1)
	doc = strings.Replace(doc, "    clients:", "    client_grants: [{client_id: Browser, audience: 'https://api.test'}]\n    clients:", 1)
	ctx := t.Context()
	st := memory.New()
	w := testWrapper(t)
	f, e := Parse([]byte(doc))
	if e != nil {
		t.Fatal(e)
	}
	if e = Apply(ctx, st, f, fixedNow, w); e != nil {
		t.Fatal(e)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	org, _ := st.Organizations().GetByName(ctx, tn.ID, "example")
	g, e := st.ClientGrants().Find(ctx, tn.ID, "browser", "https://api.test", store.SubjectTypeClient)
	if e != nil {
		t.Fatal(e)
	}
	if g.OrganizationUsage != "require" {
		t.Fatalf("policy: %+v", g)
	}
	if yes, e := st.OrganizationsII().HasClientGrant(ctx, tn.ID, org.ID, g.ID); e != nil || !yes {
		t.Fatalf("association %v %v", yes, e)
	}
	g.OrganizationUsage = "deny"
	g.Origin = store.OriginAPI
	if e = st.ClientGrants().Update(ctx, g); e != nil {
		t.Fatal(e)
	}
	if e = Apply(ctx, st, f, fixedNow, w); e != nil {
		t.Fatal(e)
	}
	g, _ = st.ClientGrants().Find(ctx, tn.ID, "browser", "https://api.test", store.SubjectTypeClient)
	if g.OrganizationUsage != "deny" {
		t.Fatal("reseed overwrote API grant")
	}
	for _, bad := range []string{strings.Replace(doc, "client_id: Browser, audience:", "client_id: missing, audience:", 1), strings.Replace(doc, "client_id: Browser, audience: 'https://api.test'", "client_id: Browser, audience: 'https://missing.test'", 1)} {
		fresh := memory.New()
		f, e := Parse([]byte(bad))
		if e == nil {
			e = Apply(ctx, fresh, f, fixedNow, w)
		}
		if e == nil {
			t.Fatal("bad grant ref accepted")
		}
		if _, e = fresh.Tenants().GetByName(ctx, "acme"); e == nil {
			t.Fatal("partial invalid grant batch")
		}
	}
}

func TestOrganizationsIISeedCreateOnlyBatchRollback(t *testing.T) {
	ctx := t.Context()
	st := memory.New()
	w := testWrapper(t)
	base := `tenants:
- name: acme
  clients: [{client_id: browser, name: Browser, app_type: spa, token_endpoint_auth_method: none}]
  resource_servers: [{name: API, identifier: 'https://api.test', scopes: [{value: read}, {value: write}]}]
  client_grants: [{client_id: browser, audience: 'https://api.test', scopes: [read]}]
`
	f, e := Parse([]byte(base))
	if e != nil {
		t.Fatal(e)
	}
	if e = Apply(ctx, st, f, fixedNow, w); e != nil {
		t.Fatal(e)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	// Legacy apply would change a seed-owned grant's scopes before reaching the
	// final bad organization. The outer transaction must restore those scopes.
	bad := strings.Replace(base, "scopes: [read]", "scopes: [write]", 1) + `  organizations:
  - name: first-valid
    clients: [{client_id: Browser, use_for_member_access: true}]
  - name: last-invalid
    clients: [{client_id: missing, use_for_member_access: true}]
`
	f, e = Parse([]byte(bad))
	if e != nil {
		t.Fatal(e)
	}
	if e = Apply(ctx, st, f, fixedNow, w); e == nil {
		t.Fatal("bad reference accepted")
	}
	for _, name := range []string{"first-valid", "last-invalid"} {
		if _, e = st.Organizations().GetByName(ctx, tn.ID, name); e == nil {
			t.Fatalf("partial organization %s", name)
		}
	}
	g, e := st.ClientGrants().Find(ctx, tn.ID, "browser", "https://api.test", store.SubjectTypeClient)
	if e != nil || len(g.Scopes) != 1 || g.Scopes[0] != "read" {
		t.Fatalf("partial grant scope change: %+v %v", g, e)
	}
}
