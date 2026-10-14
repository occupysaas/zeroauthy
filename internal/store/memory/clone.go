package memory

import (
	"maps"
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

func cloneSigningKey(k *store.SigningKey) *store.SigningKey {
	out := *k
	out.PrivateKey = slices.Clone(k.PrivateKey)
	out.PublicJWK = slices.Clone(k.PublicJWK)
	return &out
}

func cloneConnection(c *store.Connection) *store.Connection {
	out := *c
	out.EnabledClients = slices.Clone(c.EnabledClients)
	return &out
}

func cloneUser(u *store.User) *store.User {
	out := *u
	out.Identities = slices.Clone(u.Identities)
	if u.LastLogin != nil {
		t := *u.LastLogin
		out.LastLogin = &t
	}
	return &out
}

func cloneSession(s *store.LoginSession) *store.LoginSession {
	out := *s
	out.ClientIDs = slices.Clone(s.ClientIDs)
	return &out
}

func cloneAuthTransaction(t *store.AuthTransaction) *store.AuthTransaction {
	out := *t
	out.Params = maps.Clone(t.Params)
	return &out
}

func cloneAuthCode(c *store.AuthCode) *store.AuthCode {
	out := *c
	out.Scopes = slices.Clone(c.Scopes)
	if c.UsedAt != nil {
		t := *c.UsedAt
		out.UsedAt = &t
	}
	return &out
}

func cloneRefreshToken(t *store.RefreshToken) *store.RefreshToken {
	out := *t
	out.Scopes = slices.Clone(t.Scopes)
	if t.RotatedAt != nil {
		v := *t.RotatedAt
		out.RotatedAt = &v
	}
	if t.RevokedAt != nil {
		v := *t.RevokedAt
		out.RevokedAt = &v
	}
	return &out
}
