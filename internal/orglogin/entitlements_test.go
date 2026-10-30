package orglogin

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
)

func entitlementFixture(t *testing.T) (*memory.Store, *store.Organization, *store.Client) {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	c := &store.Client{TenantID: "t", ClientID: "client", Name: "app", IsFirstParty: true, OrganizationUsage: store.OrgUsageAllow}
	if err := st.Clients().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	o := &store.Organization{TenantID: "t", ID: "org_0000000000000001", Name: "org", DisplayName: "org", ThirdPartyClientAccess: "block"}
	if err := st.Organizations().Create(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	return st, o, c
}
func TestOrganizationMemberEntitlement(t *testing.T) {
	st, o, c := entitlementFixture(t)
	ctx := context.Background()
	if err := CheckMemberClient(ctx, st, "t", o.ID, c.ClientID); err != nil {
		t.Fatal(err)
	}
	o.IsAppEntitlementActive = true
	if err := st.Organizations().Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := CheckMemberClient(ctx, st, "t", o.ID, c.ClientID); !errors.Is(err, ErrNotMember) {
		t.Fatalf("absent association: %v", err)
	}
	for _, enabled := range []bool{false, true} {
		if err := st.OrganizationsII().PutClients(ctx, "t", o.ID, []store.OrganizationClient{{ClientID: c.ClientID, UseForMemberAccess: enabled}}); err != nil {
			t.Fatal(err)
		}
		err := CheckMemberClient(ctx, st, "t", o.ID, c.ClientID)
		if (err == nil) != enabled {
			t.Fatalf("enabled=%v err=%v", enabled, err)
		}
	}

}
func TestOrganizationEntitlementPickerBeforeLimit(t *testing.T) {
	st, o, c := entitlementFixture(t)
	ctx := context.Background()
	conn := &store.Connection{TenantID: "t", ID: "con_0000000000000001", Name: "db", Strategy: "auth0"}
	if err := st.Connections().Create(ctx, conn); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 22; i++ {
		x := *o
		x.ID = fmt.Sprintf("org_%016d", i+2)
		x.Name = fmt.Sprintf("org%d", i)
		x.DisplayName = x.Name
		x.IsAppEntitlementActive = true
		if err := st.Organizations().Create(ctx, &x, []store.OrganizationConnection{{ConnectionID: conn.ID, AssignMembershipOnLogin: true, ShowAsButton: true}}); err != nil {
			t.Fatal(err)
		}
		if i == 21 {
			if err := st.OrganizationsII().PutClients(ctx, "t", x.ID, []store.OrganizationClient{{ClientID: c.ClientID, UseForMemberAccess: true}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	choices, auto, err := PickerChoicesForClient(ctx, st, "t", "user", conn.ID, c)
	if err != nil || len(choices) != 0 || auto == nil || auto.ID != "org_0000000000000023" {
		t.Fatalf("choices=%v auto=%v err=%v", choices, auto, err)
	}
}

type entitlementLegacyStore struct{ store.Store }

func (entitlementLegacyStore) OrganizationsIISupported() bool { return false }
func (entitlementLegacyStore) CheckOrganizationsIISupport(context.Context) error {
	return store.ErrOrganizationsIIUnavailable
}
func (entitlementLegacyStore) OrganizationsII() store.OrganizationsII {
	return store.UnimplementedOrganizationsII{}
}
func TestOrganizationMemberEntitlementLegacyPlugin(t *testing.T) {
	st, o, c := entitlementFixture(t)
	ctx := context.Background()
	legacy := entitlementLegacyStore{st}
	if err := CheckMemberClient(ctx, legacy, "t", o.ID, c.ClientID); err != nil {
		t.Fatalf("legacy defaults %v", err)
	}
	o.IsAppEntitlementActive = true
	if err := st.Organizations().Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := CheckMemberClient(ctx, legacy, "t", o.ID, c.ClientID); !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
		t.Fatalf("active policy %v", err)
	}
}

func TestOrganizationM2MEligibility(t *testing.T) {
	st, o, c := entitlementFixture(t)
	ctx := context.Background()
	g := &store.ClientGrant{TenantID: "t", ID: "cgr_machine", ClientID: c.ClientID, SubjectType: store.SubjectTypeClient, OrganizationUsage: "allow", AllowAnyOrganization: true}
	if err := CheckMachineGrant(ctx, st, "t", nil, o.ID); !errors.Is(err, ErrNotMember) {
		t.Fatal(err)
	}
	wrong := *g
	wrong.TenantID = "other"
	if err := CheckMachineGrant(ctx, st, "t", &wrong, o.ID); !errors.Is(err, ErrNotMember) {
		t.Fatal(err)
	}
	user := *g
	user.SubjectType = store.SubjectTypeUser
	if err := CheckMachineGrant(ctx, st, "t", &user, o.ID); !errors.Is(err, ErrNotMember) {
		t.Fatal(err)
	}
	o.IsAppEntitlementActive = true
	if err := st.Organizations().Update(ctx, o); err != nil {
		t.Fatal(err)
	}
	if err := CheckMachineGrant(ctx, st, "t", g, o.ID); err != nil {
		t.Fatalf("member entitlement incorrectly gates machines: %v", err)
	}
}
