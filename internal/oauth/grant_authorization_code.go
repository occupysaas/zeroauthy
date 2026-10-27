package oauth

import (
	"context"
	"errors"
	"net/url"
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
	// A code is redeemed only on the origin that issued it; another alias
	// must not consume it (or trigger replay revocation).
	pre, err := h.Store.AuthCodes().Get(ctx, tenantID, secrets.HashToken(code))
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalidGrant("invalid authorization code")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load authorization code origin", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if res.CheckOrigin(pre.Origin) != nil {
		return nil, invalidGrant("invalid authorization code")
	}
	ac, err := h.Store.AuthCodes().Consume(ctx, tenantID, secrets.HashToken(code), now)
	// Also defend token issuance and replay revocation against a stale store read.
	if ac != nil && res.CheckOrigin(ac.Origin) != nil {
		return nil, invalidGrant("invalid authorization code")
	}
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
	var rt *store.RefreshToken
	var raw string
	if responseHasScope(resp, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.UTC().Add(absolute)
		}
		rt, raw = h.newRefreshToken(c, tenantID, refreshGrant{
			origin:   res.Origin(),
			familyID: familyForCode(ac.CodeHash), userID: user.UserID, sessionID: ac.SessionID,
			audience: ac.Audience, scopes: scopes, authTime: ac.AuthTime, expiresAt: expiresAt,
		})
	}
	// The user authenticated at /authorize, possibly long ago, so there is
	// no Version to compare (D-0043); the user must still exist and not be
	// blocked when the tokens are minted.
	err = h.mintTx(ctx, tenantID, user.UserID, nil, func(tx store.Store) error {
		if rt == nil {
			return nil
		}
		return tx.RefreshTokens().Create(ctx, rt)
	})
	switch {
	case errors.Is(err, errUserChanged):
		return nil, invalidGrant("the user is not allowed to sign in")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt != nil {
		// A replay that ran after Consume but before Create found no token
		// to revoke. Replays record ReplayedAt before revoking, so either it
		// is visible here or the replay's RevokeFamily saw the stored token.
		latest, err := h.Store.AuthCodes().Get(ctx, tenantID, ac.CodeHash)
		if err != nil {
			h.log().ErrorContext(ctx, "reload authorization code", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		if latest.ReplayedAt != nil {
			h.log().WarnContext(ctx, "authorization code replayed during exchange; revoking its refresh tokens", "tenant", tenantID, "client_id", ac.ClientID, "user_id", ac.UserID)
			if err := h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, familyForCode(ac.CodeHash), now); err != nil {
				h.log().ErrorContext(ctx, "revoke refresh tokens of a replayed code", "tenant", tenantID, "err", err)
			}
			return nil, invalidGrant("invalid authorization code")
		}
		resp.RefreshToken = &raw
	}
	return resp, nil
}
