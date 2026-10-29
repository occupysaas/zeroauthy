package oauth

import (
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// OrgClaims returns trusted organization claims. Names follow the tenant's
// current setting equally for first-party and third-party applications.
func OrgClaims(t tenant.Resolved, org *store.Organization) map[string]any {
	if org == nil {
		return nil
	}
	out := map[string]any{"org_id": org.ID}
	if names, _ := t.Tenant.SettingsExtra["allow_organization_name_in_authentication_api"].(bool); names {
		out["org_name"] = org.Name
	}
	return out
}

var errOrganizationGrant = errors.New("oauth: organization grant is no longer eligible")

// tokenOrganization never auto-enrolls. A code or refresh grant keeps its
// original organization and connection, regardless of later sessions/identities.
// In a mint transaction GetConnection holds the authorization writer lock before
// membership is read, serializing this check with organization policy changes.
func tokenOrganization(ctx context.Context, st store.Store, tid, uid, orgID, connectionID string, c *store.Client) (*store.Organization, error) {
	if orgID == "" {
		if c.OrganizationUsage == store.OrgUsageRequire {
			return nil, errOrganizationGrant
		}
		return nil, nil
	}
	if (c.OrganizationUsage != store.OrgUsageAllow && c.OrganizationUsage != store.OrgUsageRequire) || connectionID == "" {
		return nil, errOrganizationGrant
	}
	if _, err := st.Organizations().GetConnection(ctx, tid, orgID, connectionID); err != nil {
		return nil, err
	}
	org, err := st.Organizations().Get(ctx, tid, orgID)
	if err != nil {
		return nil, err
	}
	if !c.IsFirstParty && org.ThirdPartyClientAccess != "allow" {
		return nil, errOrganizationGrant
	}
	member, err := st.Organizations().IsMember(ctx, tid, orgID, uid)
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, errOrganizationGrant
	}
	return org, nil
}

func (h *Handlers) organizationForToken(ctx context.Context, tid, uid, orgID, connectionID string, c *store.Client) (*store.Organization, *Error) {
	org, err := tokenOrganization(ctx, h.Store, tid, uid, orgID, connectionID, c)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, errOrganizationGrant) {
		return nil, invalidGrant("the organization grant is no longer eligible")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load token organization", "tenant", tid, "err", err)
		return nil, serverError()
	}
	return org, nil
}

// checkTokenOrganization re-reads client policy inside the final mint transaction.
func checkTokenOrganization(ctx context.Context, tx store.Store, tid, uid, orgID, connectionID, clientID string) error {
	c, err := tx.Clients().Get(ctx, tid, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return errOrganizationGrant
	}
	if err != nil {
		return err
	}
	_, err = tokenOrganization(ctx, tx, tid, uid, orgID, connectionID, c)
	if errors.Is(err, store.ErrNotFound) {
		return errOrganizationGrant
	}
	return err
}
