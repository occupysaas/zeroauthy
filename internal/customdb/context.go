package customdb

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"maps"
)

type organizationKey struct{}

// WithOrganization binds a server-validated organization to database scripts.
func WithOrganization(ctx context.Context, org *store.Organization) context.Context {
	if org == nil {
		return context.WithValue(ctx, organizationKey{}, (*store.Organization)(nil))
	}
	snapshot := *org
	snapshot.Metadata = maps.Clone(org.Metadata)
	return context.WithValue(ctx, organizationKey{}, &snapshot)
}
func scriptContext(ctx context.Context, conn *store.Connection, script string) map[string]any {
	out := map[string]any{}
	org, _ := ctx.Value(organizationKey{}).(*store.Organization)
	if script != store.ScriptDelete && org != nil && org.TenantID == conn.TenantID {
		out["organization"] = map[string]any{"id": org.ID, "name": org.Name, "display_name": org.DisplayName, "metadata": maps.Clone(org.Metadata)}
	}
	return out
}
