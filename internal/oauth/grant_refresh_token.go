package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// refreshToken implements RFC 6749 §6 with rotation and reuse detection
// (RFC 9700 §4.14, D-0012).
func (h *Handlers) refreshToken(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	raw := form.Get("refresh_token")
	if raw == "" {
		return nil, invalidRequest("refresh_token is required")
	}
	tenantID := res.Tenant.ID
	now := h.now().UTC()
	invalid := invalidGrant("invalid refresh token")

	rt, err := h.Store.RefreshTokens().GetByTokenHash(ctx, tenantID, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt.ClientID != c.ClientID {
		// Never rotate or revoke on behalf of a client that does not own the token.
		h.log().WarnContext(ctx, "refresh token presented by another client", "tenant", tenantID, "client_id", c.ClientID, "owner", rt.ClientID)
		return nil, invalid
	}
	if rt.RevokedAt != nil {
		return nil, invalid
	}
	// A rotated token presented outside the leeway is reuse. Detect it before
	// any other check so those checks cannot mask it or probe the family.
	if rt.Rotating && rt.RotatedAt != nil {
		leeway := time.Duration(c.RefreshToken.Leeway) * time.Second
		if leeway <= 0 || !now.Before(rt.RotatedAt.Add(leeway)) {
			h.logRefreshReuse(ctx, tenantID, c.ClientID, rt)
			if err := h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, rt.FamilyID, now); err != nil {
				h.log().ErrorContext(ctx, "revoke refresh token family", "tenant", tenantID, "family", rt.FamilyID, "err", err)
			}
			return nil, invalid
		}
	}
	if refreshExpired(rt, now) {
		return nil, invalid
	}
	if aud := form.Get("audience"); aud != "" && aud != rt.Audience {
		return nil, invalidRequest("audience does not match the refresh token")
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, rt.Audience)
	if oerr != nil {
		return nil, oerr
	}
	// Requested scopes are filtered as issuance filters them, so scopes the
	// API does not define are ignored; what remains may only narrow. If
	// nothing remains, the token's scopes apply, as without a scope.
	scopes := rt.Scopes
	if requested := userScopes(strings.Fields(form.Get("scope")), rs, true); len(requested) > 0 {
		for _, s := range requested {
			if !slices.Contains(rt.Scopes, s) {
				return nil, invalidScope(fmt.Sprintf("scope %q was not granted to this refresh token", s))
			}
		}
		scopes = requested
	}

	user, oerr := h.activeUser(ctx, tenantID, rt.UserID)
	if oerr != nil {
		return nil, oerr
	}
	// Re-filter in case the API dropped a scope since the token was issued.
	scopes = userScopes(scopes, rs, true)
	d, oerr := h.decide(ctx, tenantID, access.Refresh, c, rs, scopes)
	if oerr != nil {
		return nil, oerr
	}
	scopes = d.Scopes
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes,
		sessionID: rt.SessionID, authTime: rt.AuthTime,
	})
	if oerr != nil {
		return nil, oerr
	}

	// The minted tokens are only sent once the refresh token is consumed,
	// in a transaction that checks the user is still at the Version loaded
	// above. The store's own error from Rotate or Touch is kept apart and
	// the transaction commits, so a family revoked for reuse stays revoked.
	version := user.Version
	var writeErr error
	var nextRaw string
	err = h.mintTx(ctx, tenantID, rt.UserID, &version, func(tx store.Store) error {
		if rt.Rotating {
			next, raw := h.newRefreshToken(c, tenantID, refreshGrant{
				familyID: rt.FamilyID, userID: rt.UserID, sessionID: rt.SessionID, audience: rt.Audience,
				scopes: rt.Scopes, authTime: rt.AuthTime, expiresAt: rt.ExpiresAt,
			})
			next.Rotating = true
			nextRaw = raw
			writeErr = tx.RefreshTokens().Rotate(ctx, tenantID, rt.ID, next, now, time.Duration(c.RefreshToken.Leeway)*time.Second)
			return nil
		}
		if _, idle := refreshLifetimes(c.RefreshToken); idle > 0 {
			idleAt := now.Add(idle)
			if !rt.ExpiresAt.IsZero() && idleAt.After(rt.ExpiresAt) {
				idleAt = rt.ExpiresAt
			}
			writeErr = tx.RefreshTokens().Touch(ctx, tenantID, rt.ID, idleAt)
		}
		return nil
	})
	if errors.Is(err, errUserChanged) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err == nil {
		err = writeErr
	}
	switch {
	case rt.Rotating && errors.Is(err, store.ErrAlreadyUsed):
		h.logRefreshReuse(ctx, tenantID, c.ClientID, rt)
		return nil, invalid
	case errors.Is(err, store.ErrNotFound):
		return nil, invalid
	case err != nil && rt.Rotating:
		h.log().ErrorContext(ctx, "rotate refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	case err != nil:
		h.log().ErrorContext(ctx, "extend refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt.Rotating {
		resp.RefreshToken = &nextRaw
	}
	return resp, nil
}

func (h *Handlers) logRefreshReuse(ctx context.Context, tenantID, clientID string, rt *store.RefreshToken) {
	h.log().WarnContext(ctx, "refresh token reuse detected; family revoked",
		"tenant", tenantID, "client_id", clientID, "user_id", rt.UserID, "family", rt.FamilyID)
}
