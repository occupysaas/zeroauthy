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

// checkRefreshRotation validates a rotating presentation without a successor.
// Legacy stores enforce only the time window on an already-rotated token.
func checkRefreshRotation(ctx context.Context, repo store.RefreshTokens, rt *store.RefreshToken, policy store.RefreshTokenPolicy, now time.Time, capable bool) error {
	leeway := time.Duration(policy.Leeway) * time.Second
	if capable {
		return repo.CheckRotation(ctx, rt.TenantID, rt.ID, now, leeway)
	}
	if rt.RotatedAt == nil || (leeway > 0 && now.Before(rt.RotatedAt.Add(leeway))) {
		return nil
	}
	if err := repo.RevokeFamily(ctx, rt.TenantID, rt.FamilyID, now); err != nil {
		return err
	}
	return store.ErrAlreadyUsed
}

// finishRefresh runs after the final transaction has locked policy and user
// state. Re-read the token because revocation, conversion or an idle deadline
// change may have landed while signing or executing Actions.
func finishRefresh(ctx context.Context, repo store.RefreshTokens, presented *store.RefreshToken, client *store.Client, origin string, now time.Time, keep, capable bool) (string, error) {
	current, err := repo.GetByTokenHash(ctx, presented.TenantID, presented.TokenHash)
	if err != nil {
		return "", err
	}
	if current.ID != presented.ID || current.RevokedAt != nil {
		return "", store.ErrNotFound
	}
	expired := refreshExpired(current, now)
	if expired || !keep {
		// No successor write will check reuse. A stale parent still revokes
		// its family, including when the presentation has expired.
		if current.Rotating {
			if err := checkRefreshRotation(ctx, repo, current, client.RefreshToken, now, capable); err != nil {
				return "", err
			}
		}
		if expired {
			return "", store.ErrNotFound
		}
		return "", nil
	}
	plan := planRefresh(current, client.RefreshToken, capable)
	return plan.exchange(ctx, repo, current, client, origin, now)
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
