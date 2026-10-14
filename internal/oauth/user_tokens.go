package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// oidcScopes are the user-flow scopes zeroauthy grants without an API.
var oidcScopes = []string{"openid", "profile", "email"}

// userScopes keeps requested OIDC scopes, offline_access when refresh
// tokens may be issued, and, when an API is the audience, requested scopes
// that API defines.
func userScopes(requested []string, rs *store.ResourceServer, offline bool) []string {
	var out []string
	for _, s := range requested {
		ok := slices.Contains(oidcScopes, s) || (offline && s == "offline_access")
		if !ok && rs != nil {
			ok = slices.ContainsFunc(rs.Scopes, func(d store.Scope) bool { return d.Value == s })
		}
		if ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// activeUser loads the user a grant was issued to. A deleted or blocked
// user gets invalid_grant.
func (h *Handlers) activeUser(ctx context.Context, tenantID, userID string) (*store.User, *Error) {
	user, err := h.Store.Users().Get(ctx, tenantID, userID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Blocked) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load user", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return user, nil
}

// audienceFor loads the API named by aud ("" means none) and the lifetime
// of access tokens issued for it.
func (h *Handlers) audienceFor(ctx context.Context, tenantID, aud string) (*store.ResourceServer, time.Duration, *Error) {
	if aud == "" {
		return nil, DefaultAccessTokenLifetime, nil
	}
	rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, invalidGrant("the requested audience no longer exists")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "err", err)
		return nil, 0, serverError()
	}
	lifetime := DefaultAccessTokenLifetime
	if rs.TokenLifetime > 0 {
		lifetime = time.Duration(rs.TokenLifetime) * time.Second
	}
	return rs, lifetime, nil
}

// userTokens describes the tokens of one user-flow token response.
type userTokens struct {
	user      *store.User
	rs        *store.ResourceServer // nil: the token is for /userinfo only
	lifetime  time.Duration
	scopes    []string
	nonce     string
	sessionID string
	authTime  time.Time
	// grantType becomes the access token's gty claim; empty omits it.
	grantType string
}

// mintUserTokens returns an access token and, with scope openid, an ID
// token (D-0008).
func (h *Handlers) mintUserTokens(ctx context.Context, res tenant.Resolved, c *store.Client, ut userTokens) (*authapi.TokenResponse, *Error) {
	tenantID := res.Tenant.ID
	userinfo := res.Issuer() + "userinfo"
	openid := slices.Contains(ut.scopes, "openid")
	var audiences []string
	switch {
	case ut.rs != nil && openid:
		audiences = []string{ut.rs.Identifier, userinfo}
	case ut.rs != nil:
		audiences = []string{ut.rs.Identifier}
	default:
		audiences = []string{userinfo}
	}
	accessToken, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID: tenantID, Issuer: res.Issuer(), Subject: ut.user.UserID, Audience: audiences,
		ClientID: c.ClientID, Scopes: ut.scopes, Lifetime: ut.lifetime, GrantType: ut.grantType,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	resp := &authapi.TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(ut.lifetime / time.Second)}
	if len(ut.scopes) > 0 {
		s := strings.Join(ut.scopes, " ")
		resp.Scope = &s
	}
	if openid {
		idToken, err := h.Minter.IDToken(ctx, IDTokenParams{
			TenantID: tenantID, Issuer: res.Issuer(), ClientID: c.ClientID, User: ut.user, Scopes: ut.scopes,
			Nonce: ut.nonce, SessionID: ut.sessionID, AuthTime: ut.authTime, AccessToken: accessToken,
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
