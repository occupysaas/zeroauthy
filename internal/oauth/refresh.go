package oauth

import (
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Refresh token lifetimes when a client's policy is expiring but sets no
// value (D-0012).
const (
	DefaultRefreshTokenLifetime     = 31557600 * time.Second
	DefaultRefreshTokenIdleLifetime = 2592000 * time.Second
)

// familyForCode is the refresh token family started by an authorization
// code. Deriving it from the code hash lets a replayed code revoke the
// family without the code record pointing at it.
func familyForCode(codeHash string) string {
	return "rtf_" + secrets.HashToken("family:" + codeHash)[:32]
}

// offlineAllowed reports whether refresh tokens may be issued: the client
// must be allowed the refresh_token grant and, when an API is the
// audience, the API must allow offline access.
func offlineAllowed(c *store.Client, rs *store.ResourceServer) bool {
	return slices.Contains(c.GrantTypes, "refresh_token") && (rs == nil || rs.AllowOfflineAccess)
}

// refreshLifetimes returns the absolute and idle lifetimes for a policy;
// zero means the token does not expire that way.
func refreshLifetimes(p store.RefreshTokenPolicy) (absolute, idle time.Duration) {
	if !p.Expiring {
		return 0, 0
	}
	absolute, idle = DefaultRefreshTokenLifetime, DefaultRefreshTokenIdleLifetime
	if p.TokenLifetime > 0 {
		absolute = time.Duration(p.TokenLifetime) * time.Second
	}
	if p.IdleTokenLifetime > 0 {
		idle = time.Duration(p.IdleTokenLifetime) * time.Second
	}
	return absolute, idle
}

// refreshExpired reports whether rt has passed its absolute or idle expiry.
func refreshExpired(rt *store.RefreshToken, now time.Time) bool {
	return (!rt.ExpiresAt.IsZero() && !now.Before(rt.ExpiresAt)) ||
		(!rt.IdleExpiresAt.IsZero() && !now.Before(rt.IdleExpiresAt))
}

// refreshGrant is what a refresh token carries forward through rotation.
type refreshGrant struct {
	// origin is the public origin the token is bound to (tenant.Resolved.Origin).
	origin                                   string
	organizationID, organizationConnectionID string
	familyID, userID, sessionID, audience    string
	scopes                                   []string
	authTime                                 time.Time
	// expiresAt is the family's absolute expiry; zero means none.
	expiresAt time.Time
}

// newRefreshToken builds a refresh token record for c and returns it with
// the token value. The idle expiry starts now and never passes expiresAt.
func (h *Handlers) newRefreshToken(c *store.Client, tenantID string, g refreshGrant) (*store.RefreshToken, string) {
	now := h.now().UTC()
	_, idle := refreshLifetimes(c.RefreshToken)
	raw := secrets.RandomString(48)
	rt := &store.RefreshToken{
		OrganizationID: g.organizationID, OrganizationConnectionID: g.organizationConnectionID,
		Origin:    g.origin,
		TenantID:  tenantID,
		ID:        "rt_" + secrets.RandomString(24),
		TokenHash: secrets.HashToken(raw),
		FamilyID:  g.familyID,
		ClientID:  c.ClientID,
		UserID:    g.userID,
		SessionID: g.sessionID,
		Scopes:    slices.Clone(g.scopes),
		Audience:  g.audience,
		AuthTime:  g.authTime,
		Rotating:  c.RefreshToken.Rotating,
		ExpiresAt: g.expiresAt,
		CreatedAt: now,
	}
	if idle > 0 {
		rt.IdleExpiresAt = now.Add(idle)
		if !g.expiresAt.IsZero() && rt.IdleExpiresAt.After(g.expiresAt) {
			rt.IdleExpiresAt = g.expiresAt
		}
	}
	return rt, raw
}
