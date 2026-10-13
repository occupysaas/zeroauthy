package memory

import (
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func cloneTenant(t *store.Tenant) *store.Tenant {
	c := *t
	c.Domains = slices.Clone(t.Domains)
	return &c
}

func cloneClient(c *store.Client) *store.Client {
	out := *c
	out.Secrets = make([]store.ClientSecret, len(c.Secrets))
	for i, sec := range c.Secrets {
		out.Secrets[i] = sec
		if sec.ExpiresAt != nil {
			exp := *sec.ExpiresAt
			out.Secrets[i].ExpiresAt = &exp
		}
	}
	if c.Secrets == nil {
		out.Secrets = nil
	}
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.Callbacks = slices.Clone(c.Callbacks)
	out.AllowedLogoutURLs = slices.Clone(c.AllowedLogoutURLs)
	out.WebOrigins = slices.Clone(c.WebOrigins)
	out.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	return &out
}

func cloneResourceServer(rs *store.ResourceServer) *store.ResourceServer {
	out := *rs
	out.Scopes = slices.Clone(rs.Scopes)
	return &out
}

func cloneClientGrant(g *store.ClientGrant) *store.ClientGrant {
	out := *g
	out.Scopes = slices.Clone(g.Scopes)
	return &out
}
