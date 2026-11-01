package events

import (
	"context"
	"net"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type Context struct {
	ClientID, ClientName                          string
	ClientMetadata                                map[string]string
	ConnectionID, ConnectionName, Strategy        string
	IP, Hostname, CustomDomain, Method, UserAgent string
	request                                       bool
}
type contextKey struct{}

func WithContext(ctx context.Context, c Context) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}
func FromRequest(r *http.Request) Context {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	c := Context{IP: httpx.ClientIP(r, false), Hostname: host, Method: r.Method, UserAgent: r.UserAgent(), request: true}
	if resolved, ok := tenant.FromContext(r.Context()); ok && resolved.Tenant != nil && resolved.Host != "" {
		c.Hostname = resolved.Host
		if resolved.Host != resolved.Tenant.CanonicalHost {
			c.CustomDomain = resolved.Host
		}
	}
	return c
}
func eventContext(ctx context.Context, tenantID string) map[string]any {
	out := map[string]any{"tenant": map[string]any{"id": tenantID}}
	c, _ := ctx.Value(contextKey{}).(Context)
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
	if c.request || c.Method != "" || c.Hostname != "" || c.IP != "" {
		r := map[string]any{"geo": map[string]any{}, "hostname": c.Hostname, "ip": c.IP, "method": c.Method, "user_agent": c.UserAgent}
		if c.CustomDomain != "" {
			r["custom_domain"] = c.CustomDomain
		}
		out["request"] = r
	}
	return out
}
