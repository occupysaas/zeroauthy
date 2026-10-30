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
