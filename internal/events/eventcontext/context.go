// Package eventcontext carries trusted event attribution without depending on
// capture or serialization, so authentication layers can use it without cycles.
package eventcontext

import (
	"context"
	"net"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type Context struct {
	ClientID, ClientName                          string
	ClientMetadata                                map[string]string
	ConnectionID, ConnectionName, Strategy        string
	IP, Hostname, CustomDomain, Method, UserAgent string
	Request                                       bool
}
type contextKey struct{}

// FromContext returns the attribution already established by trusted application layers.
func FromContext(ctx context.Context) Context {
	c, _ := ctx.Value(contextKey{}).(Context)
	return c
}

func WithContext(ctx context.Context, c Context) context.Context {
	return context.WithValue(ctx, contextKey{}, c)
}
func FromRequest(r *http.Request) Context {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	c := FromContext(r.Context())
	c.IP, c.Hostname, c.Method, c.UserAgent, c.CustomDomain, c.Request = httpx.ClientIP(r, false), host, r.Method, r.UserAgent(), "", true
	if resolved, ok := tenant.FromContext(r.Context()); ok && resolved.Tenant != nil && resolved.Host != "" {
		c.Hostname = resolved.Host
		if resolved.Host != resolved.Tenant.CanonicalHost {
			c.CustomDomain = resolved.Host
		}
	}
	return c
}

// Enrich retains request and caller attribution while adding resolved entities.
// Clients currently have no persisted client_metadata; emit an empty map rather
// than borrowing request fields or secret-bearing configuration.
func Enrich(ctx context.Context, client *store.Client, connection *store.Connection) context.Context {
	c := FromContext(ctx)
	if client != nil {
		c.ClientID, c.ClientName, c.ClientMetadata = client.ClientID, client.Name, map[string]string{}
	}
	if connection != nil {
		c.ConnectionID, c.ConnectionName, c.Strategy = connection.ID, connection.Name, connection.Strategy
	}
	return WithContext(ctx, c)
}
