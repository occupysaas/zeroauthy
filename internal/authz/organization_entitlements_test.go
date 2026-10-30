package authz

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"testing"
)

func TestOrganizationMemberEntitlementExplicit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	org := addOrg(t, f.st, f.tenant.ID, "", "entitlement", "allow")
	client := &store.Client{TenantID: f.tenant.ID, ClientID: "entitlement-client", IsFirstParty: true, OrganizationUsage: store.OrgUsageAllow}
	if err := f.st.Clients().Create(ctx, client); err != nil {
		t.Fatal(err)
	}
	org.IsAppEntitlementActive = true
	if err := f.st.Organizations().Update(ctx, org); err != nil {
		t.Fatal(err)
	}
	res := tenant.Resolved{Tenant: f.tenant}
	if _, err := ResolveOrganization(ctx, f.st, res, client, org.ID); err == nil || err.Code != "access_denied" {
		t.Fatalf("absent association %+v", err)
	}
	if err := f.st.OrganizationsII().PutClients(ctx, f.tenant.ID, org.ID, []store.OrganizationClient{{ClientID: client.ClientID, UseForMemberAccess: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveOrganization(ctx, f.st, res, client, org.ID); err != nil {
		t.Fatal(err)
	}
	client.IsFirstParty = false
	org.ThirdPartyClientAccess = "block"
	if err := f.st.Organizations().Update(ctx, org); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveOrganization(ctx, f.st, res, client, org.ID); err == nil || err.Code != "access_denied" {
		t.Fatalf("third party bypass %+v", err)
	}
	client.IsFirstParty = true
	client.OrganizationUsage = store.OrgUsageDeny
	if _, err := ResolveOrganization(ctx, f.st, res, client, org.ID); err == nil || err.Code != "invalid_request" {
		t.Fatalf("client policy bypass %+v", err)
	}
}
