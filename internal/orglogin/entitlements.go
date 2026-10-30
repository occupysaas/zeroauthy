package orglogin

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// CheckMemberClient applies the additional application gate. Callers retain
// their membership, connection and client organization policy checks. In a
// transaction the organization read holds the SQL tenant policy lock through
// final issuance, serializing eligibility with revocation.
func CheckMemberClient(ctx context.Context, st store.Store, tenantID, orgID, clientID string) error {
	org, err := st.Organizations().Get(ctx, tenantID, orgID)
	if err != nil {
		return err
	}
	if !org.IsAppEntitlementActive {
		return nil
	}
	if capability, ok := st.(store.OrganizationsIISupporter); ok {
		if err := capability.CheckOrganizationsIISupport(ctx); err != nil {
			return err
		}
	}
	if !store.OrganizationsIISupported(st) {
		return store.ErrOrganizationsIIUnavailable
	}
	link, err := st.OrganizationsII().GetClient(ctx, tenantID, orgID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotMember
	}
	if err != nil {
		return err
	}
	if !link.UseForMemberAccess {
		return ErrNotMember
	}
	return nil
}

// CheckMachineGrant applies grant organization policy only. Member application
// entitlements and organization roles never authorize machine credentials.
// Call inside the mint transaction: organization/grant reads hold policy locks.
func CheckMachineGrant(ctx context.Context, st store.Store, tenantID string, grant *store.ClientGrant, orgID string) error {
	if grant == nil || grant.TenantID != tenantID || (grant.SubjectType != "" && grant.SubjectType != store.SubjectTypeClient) {
		return ErrNotMember
	}
	usage := grant.OrganizationUsage
	if orgID == "" {
		if usage == store.OrgUsageRequire {
			return ErrNotMember
		}
		return nil
	}
	if usage != store.OrgUsageAllow && usage != store.OrgUsageRequire {
		return ErrNotMember
	}
	if capability, ok := st.(store.OrganizationsIISupporter); ok {
		if err := capability.CheckOrganizationsIISupport(ctx); err != nil {
			return err
		}
	}
	if !store.OrganizationsIISupported(st) {
		return store.ErrOrganizationsIIUnavailable
	}
	org, err := st.Organizations().Get(ctx, tenantID, orgID)
	if err != nil {
		return err
	}
	client, err := st.Clients().Get(ctx, tenantID, grant.ClientID)
	if err != nil {
		return err
	}
	if !client.IsFirstParty && (grant.AllowAnyOrganization || org.ThirdPartyClientAccess != "allow") {
		return ErrNotMember
	}
	if grant.AllowAnyOrganization {
		return nil
	}
	associated, err := st.OrganizationsII().HasClientGrant(ctx, tenantID, orgID, grant.ID)
	if err != nil {
		return err
	}
	if !associated {
		return ErrNotMember
	}
	return nil
}
