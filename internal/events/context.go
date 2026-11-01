package events

import (
	"context"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/events/eventcontext"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Context is the attribution attached by authentication and HTTP layers.
type Context = eventcontext.Context

// WithContext replaces attribution. An empty Context deliberately resets job and seed origins.
func WithContext(ctx context.Context, c Context) context.Context {
	return eventcontext.WithContext(ctx, c)
}
func FromRequest(r *http.Request) Context { return eventcontext.FromRequest(r) }

// Enrich adds resolved entities while retaining attribution already established.
func Enrich(ctx context.Context, client *store.Client, connection *store.Connection) context.Context {
	return eventcontext.Enrich(ctx, client, connection)
}
func eventContext(ctx context.Context, tenantID string) map[string]any {
	out := map[string]any{"tenant": map[string]any{"id": tenantID}}
	c := eventcontext.FromContext(ctx)
	if c.ClientID != "" {
		metadata := c.ClientMetadata
		if metadata == nil {
			metadata = map[string]string{}
		}
		out["client"] = map[string]any{"id": c.ClientID, "name": c.ClientName, "metadata": metadata}
	}
	if c.ConnectionID != "" {
		out["connection"] = map[string]any{"id": c.ConnectionID, "name": c.ConnectionName, "strategy": c.Strategy}
	}
	if c.Request || c.Method != "" || c.Hostname != "" || c.IP != "" {
		r := map[string]any{"geo": map[string]any{}, "hostname": c.Hostname, "ip": c.IP, "method": c.Method, "user_agent": c.UserAgent}
		if c.CustomDomain != "" {
			r["custom_domain"] = c.CustomDomain
		}
		out["request"] = r
	}
	return out
}
