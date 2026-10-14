package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// authorizationCode implements RFC 6749 §4.1.3 with RFC 7636 PKCE.
func (h *Handlers) authorizationCode(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	code := form.Get("code")
	if code == "" {
		return nil, invalidRequest("code is required")
	}
	tenantID := res.Tenant.ID
	now := h.now()
	ac, err := h.Store.AuthCodes().Consume(ctx, tenantID, secrets.HashToken(code), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, invalidGrant("invalid authorization code")
	case errors.Is(err, store.ErrAlreadyUsed):
		// RFC 9700 §4.5: a replayed code may be stolen; revoke what it issued.
		h.log().WarnContext(ctx, "authorization code reused; revoking its refresh tokens", "tenant", tenantID, "client_id", ac.ClientID, "user_id", ac.UserID)
		if err := h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, familyForCode(ac.CodeHash), now); err != nil {
			h.log().ErrorContext(ctx, "revoke refresh tokens of a replayed code", "tenant", tenantID, "err", err)
		}
		return nil, invalidGrant("invalid authorization code")
	case err != nil:
		h.log().ErrorContext(ctx, "consume authorization code", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if ac.ClientID != c.ClientID {
		return nil, invalidGrant("invalid authorization code")
	}
	if !now.Before(ac.ExpiresAt) {
		return nil, invalidGrant("authorization code expired")
	}
	if form.Get("redirect_uri") != ac.RedirectURI {
		return nil, invalidGrant("redirect_uri does not match the authorization request")
	}
	if ac.CodeChallenge != "" {
		if !verifyPKCE(ac.CodeChallengeMethod, ac.CodeChallenge, form.Get("code_verifier")) {
			return nil, invalidGrant("code_verifier does not match the code_challenge")
		}
	} else {
		if c.TokenEndpointAuthMethod == store.AuthMethodNone {
			return nil, invalidGrant("PKCE is required for public applications")
		}
		// RFC 9700 §4.8.2: refuse a verifier for a code issued without a challenge.
		if form.Get("code_verifier") != "" {
			return nil, invalidGrant("code_verifier was sent but the authorization request had no code_challenge")
		}
	}

	user, oerr := h.activeUser(ctx, tenantID, ac.UserID)
	if oerr != nil {
		return nil, oerr
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, ac.Audience)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(ac.Scopes, rs, offlineAllowed(c, rs))
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes,
		nonce: ac.Nonce, sessionID: ac.SessionID, authTime: ac.AuthTime,
	})
	if oerr != nil {
		return nil, oerr
	}
	if slices.Contains(scopes, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.UTC().Add(absolute)
		}
		rt, raw := h.newRefreshToken(c, tenantID, refreshGrant{
			familyID: familyForCode(ac.CodeHash), userID: user.UserID, sessionID: ac.SessionID,
			audience: ac.Audience, scopes: scopes, authTime: ac.AuthTime, expiresAt: expiresAt,
		})
		if err := h.Store.RefreshTokens().Create(ctx, rt); err != nil {
			h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		resp.RefreshToken = &raw
	}
	return resp, nil
}
