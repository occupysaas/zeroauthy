package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// oidcScopes are the user-flow scopes zeroauthy grants without an API.
// offline_access is added when refresh tokens exist (milestone 5).
var oidcScopes = []string{"openid", "profile", "email"}

// userScopes keeps requested OIDC scopes and, when an API is the
// audience, requested scopes that API defines.
func userScopes(requested []string, rs *store.ResourceServer) []string {
	var out []string
	for _, s := range requested {
		ok := slices.Contains(oidcScopes, s)
		if !ok && rs != nil {
			ok = slices.ContainsFunc(rs.Scopes, func(d store.Scope) bool { return d.Value == s })
		}
		if ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

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
		h.log().WarnContext(ctx, "authorization code reused", "tenant", tenantID, "client_id", ac.ClientID, "user_id", ac.UserID)
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

	user, err := h.Store.Users().Get(ctx, tenantID, ac.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Blocked) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load user", "tenant", tenantID, "err", err)
		return nil, serverError()
	}

	userinfo := res.Issuer() + "userinfo"
	var rs *store.ResourceServer
	lifetime := DefaultAccessTokenLifetime
	if ac.Audience != "" {
		rs, err = h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, ac.Audience)
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalidGrant("the requested audience no longer exists")
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		if rs.TokenLifetime > 0 {
			lifetime = time.Duration(rs.TokenLifetime) * time.Second
		}
	}
	scopes := userScopes(ac.Scopes, rs)
	openid := slices.Contains(scopes, "openid")
	var audiences []string
	switch {
	case rs != nil && openid:
		audiences = []string{rs.Identifier, userinfo}
	case rs != nil:
		audiences = []string{rs.Identifier}
	default:
		audiences = []string{userinfo}
	}

	accessToken, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID: tenantID, Issuer: res.Issuer(), Subject: user.UserID, Audience: audiences,
		ClientID: c.ClientID, Scopes: scopes, Lifetime: lifetime,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	resp := &authapi.TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(lifetime / time.Second)}
	if len(scopes) > 0 {
		s := strings.Join(scopes, " ")
		resp.Scope = &s
	}
	if openid {
		idToken, err := h.Minter.IDToken(ctx, IDTokenParams{
			TenantID: tenantID, Issuer: res.Issuer(), ClientID: c.ClientID, User: user, Scopes: scopes,
			Nonce: ac.Nonce, SessionID: ac.SessionID, AuthTime: ac.AuthTime, AccessToken: accessToken,
			Lifetime: time.Duration(c.IDTokenLifetime) * time.Second,
		})
		if err != nil {
			h.log().ErrorContext(ctx, "mint id token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		resp.IdToken = &idToken
	}
	return resp, nil
}
