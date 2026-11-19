package oauth

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type refreshPlan uint8

const (
	touchRefresh refreshPlan = iota
	rotateRefresh
	convertToRotating
	convertToNonRotating
)

// The legacy protocol continues the presented token's policy. Capable stores
// atomically convert offline tokens when the client's rotation policy changes.
func planRefresh(rt *store.RefreshToken, policy store.RefreshTokenPolicy, capable bool) refreshPlan {
	if capable && rt.Access != "online" && rt.Rotating != policy.Rotating {
		if policy.Rotating {
			return convertToRotating
		}
		return convertToNonRotating
	}
	if rt.Rotating {
		return rotateRefresh
	}
	return touchRefresh
}

// exchange runs inside the final mint transaction, after organization and user
// eligibility have been checked. The store rechecks reuse under the write lock.
func (plan refreshPlan) exchange(ctx context.Context, repo store.RefreshTokens, old *store.RefreshToken, c *store.Client, origin string, now time.Time) (string, error) {
	policy := c.RefreshToken
	absolute, idle := refreshLifetimes(policy)
	if plan == touchRefresh {
		if idle == 0 {
			return "", nil
		}
		return "", repo.Touch(ctx, old.TenantID, old.ID, idleExpiresAt(now, idle, old.ExpiresAt))
	}
	family, expires := old.FamilyID, old.ExpiresAt
	if plan != rotateRefresh {
		family = "rtf_" + secrets.RandomString(32)
		expires = time.Time{}
		if absolute > 0 {
			expires = now.Add(absolute)
		}
	}
	next, raw := newRefreshTokenAt(c, old.TenantID, refreshGrant{
		origin: origin, familyID: family, userID: old.UserID, sessionID: old.SessionID,
		organizationID: old.OrganizationID, organizationConnectionID: old.OrganizationConnectionID,
		scopes: old.Scopes, audience: old.Audience, authTime: old.AuthTime, expiresAt: expires,
	}, now)
	next.Rotating = plan != convertToNonRotating
	next.Access, next.DPoPJKT = old.Access, old.DPoPJKT
	next.Metadata, next.Device, next.LastExchangedAt = old.Metadata, old.Device, old.LastExchangedAt
	leeway := time.Duration(policy.Leeway) * time.Second
	switch plan {
	case convertToRotating:
		return raw, repo.ConvertNonRotating(ctx, old.TenantID, old.ID, next)
	case convertToNonRotating:
		return raw, repo.ConvertRotating(ctx, old.TenantID, old.ID, next, now, leeway)
	default:
		return raw, repo.Rotate(ctx, old.TenantID, old.ID, next, now, leeway)
	}
}
