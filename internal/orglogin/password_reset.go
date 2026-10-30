package orglogin

import (
	"context"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// PasswordResetContext validates a bound reset context without reading or
// changing membership. An absent context preserves the legacy reset policy.
func PasswordResetContext(ctx context.Context, st store.Store, tenantID, organizationID, clientID string, conn *store.Connection) (*store.Organization, error) {
	if organizationID == "" {
		return nil, nil
	}
	if !orgrules.ValidID(organizationID) || conn == nil || conn.TenantID != tenantID || conn.Strategy != store.StrategyDatabase {
		return nil, ErrNotMember
	}
	// Reload connection policy in the caller's transaction; HTTP snapshots cannot
	// authorize a password mutation after an application has been disabled.
	fresh, err := st.Connections().Get(ctx, tenantID, conn.ID)
	if err != nil {
		return nil, err
	}
	if fresh.Name != conn.Name || fresh.Strategy != store.StrategyDatabase {
		return nil, ErrNotMember
	}
	conn = fresh
	org, err := st.Organizations().Get(ctx, tenantID, organizationID)
	if err != nil {
		return nil, err
	}
	link, err := st.Organizations().GetConnection(ctx, tenantID, organizationID, conn.ID)
	if err != nil {
		return nil, err
	}
	if link.IsEnabledSet && !link.IsEnabled {
		return nil, ErrNotMember
	}
	if clientID != "" {
		if _, err = st.Clients().Get(ctx, tenantID, clientID); err != nil {
			return nil, err
		}
		if !slices.Contains(conn.EnabledClients, clientID) {
			return nil, ErrNotMember
		}
	}
	if err = CheckMemberClient(ctx, st, tenantID, organizationID, clientID); err != nil {
		return nil, err
	}
	return org, nil
}
