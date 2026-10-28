package oauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
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
	return h.activeUserBlocked(ctx, tenantID, userID, "the user is not allowed to sign in")
}

// activeUserBlocked is activeUser with the invalid_grant text a blocked user
// gets (the refresh grant says what Auth0 observed: "user is blocked").
func (h *Handlers) activeUserBlocked(ctx context.Context, tenantID, userID, blocked string) (*store.User, *Error) {
	user, err := h.Store.Users().Get(ctx, tenantID, userID)
	if err == nil && user.Blocked {
		return nil, invalidGrant(blocked)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load user", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return user, nil
}

// errUserChanged is returned by mintTx when the user is gone, blocked or,
// when a version is given, no longer at that Version.
var errUserChanged = errors.New("oauth: the user changed since it was loaded")

// errUserBlocked is the errUserChanged that mintTx returns for a blocked
// user, so a grant can word that case on its own.
var errUserBlocked = fmt.Errorf("%w: the user is blocked", errUserChanged)

// mintTx runs write, the store writes that mint a grant's tokens (nil for
// none), in a transaction that first re-reads and locks the user
// (GetForUpdate), so a reset or revocation, which locks or writes the user
// first, runs wholly before or wholly after the mint. When the user is
// gone or blocked, or version is non-nil and the user's Version differs
// from it, nothing is written and mintTx returns errUserChanged: a reset,
// block or session revocation landed between the grant loading the user
// and minting. Tokens issued earlier are not affected (D-0043).
func (h *Handlers) mintTx(ctx context.Context, tenantID, userID string, version *int64, write func(tx store.Store) error) error {
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		u, err := tx.Users().GetForUpdate(ctx, tenantID, userID)
		if errors.Is(err, store.ErrNotFound) {
			return errUserChanged
		}
		if err != nil {
			return err
		}
		if u.Blocked {
			return errUserBlocked
		}
		if version != nil && u.Version != *version {
			return errUserChanged
		}
		if write == nil {
			return nil
		}
		return write(tx)
	})
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
	// omitAtHash leaves at_hash out of the ID token.
	omitAtHash bool
	// effects are the post-login flow's: custom claims and accessToken
	// scope edits. nil when no Action ran.
	effects *actions.Effects
}

// mintUserTokens returns an access token and, with scope openid, an ID
// token (D-0008). Scope order (spec §7): ut.scopes already carry the
// Actions' target-scope edits and API-definition and client-policy
// filtering; RBAC filters them here, and accessToken.addScope/removeScope
// edit only the access token's scope, which the response's scope equals.
// The ID token, the audiences and refresh state keep the authorized set.
// offline reports that a refresh token may be issued: offline_access is in
// the authorized set and the final scope.
func (h *Handlers) mintUserTokens(ctx context.Context, res tenant.Resolved, c *store.Client, ut userTokens) (resp *authapi.TokenResponse, offline bool, oerr *Error) {
	tenantID := res.Tenant.ID
	requestedScopes := len(ut.scopes) > 0
	var frozen *actions.RBACSnapshot
	if ut.effects != nil {
		frozen = ut.effects.RBAC
	}
	auth, authErr := h.authorizeUserToken(ctx, tenantID, ut.user.UserID, ut.rs, ut.scopes, frozen)
	if authErr != nil {
		return nil, false, authErr
	}
	ut.rs, ut.scopes = auth.API, auth.Scopes
	if ut.rs != nil && !ut.rs.IsSystem {
		decision, e := h.decide(ctx, tenantID, access.Refresh, c, ut.rs, ut.scopes)
		if e != nil {
			return nil, false, e
		}
		ut.scopes = decision.Scopes
		ut.lifetime = DefaultAccessTokenLifetime
		if ut.rs.TokenLifetime > 0 {
			ut.lifetime = time.Duration(ut.rs.TokenLifetime) * time.Second
		}
	}
	dialect := ""
	if ut.rs != nil {
		dialect = ut.rs.TokenDialect
	}
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
	operator, oerr := h.operatorClaim(ctx, res, c, ut)
	if oerr != nil {
		return nil, false, oerr
	}
	final := ut.effects.ApplyScopes(nil, ut.scopes)
	var accessClaims, idClaims map[string]any
	if ut.effects != nil {
		// Non-namespaced claims never reach the Management API.
		mgmt := ut.rs != nil && ut.rs.IsSystem
		var err error
		if accessClaims, err = actions.FilterClaims(actions.ClaimAccessToken, nil, ut.effects.AccessClaims, mgmt); err == nil {
			idClaims, err = actions.FilterClaims(actions.ClaimIDToken, nil, ut.effects.IDClaims, false)
		}
		if err != nil {
			h.log().ErrorContext(ctx, "apply Action custom claims", "tenant", tenantID, "err", err)
			return nil, false, serverError()
		}
	}
	accessToken, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID: tenantID, Issuer: res.Issuer(), Subject: ut.user.UserID, Audience: audiences,
		ClientID: c.ClientID, Scopes: final, Lifetime: ut.lifetime, GrantType: ut.grantType,
		Operator: operator, TokenDialect: dialect, Permissions: auth.Permissions, IncludePermissions: auth.IncludePermissions,
		CustomClaims: accessClaims,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, false, serverError()
	}
	resp = &authapi.TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int(ut.lifetime / time.Second)}
	if len(final) > 0 || requestedScopes {
		s := strings.Join(final, " ")
		resp.Scope = &s
	}
	offline = slices.Contains(ut.scopes, "offline_access") && slices.Contains(final, "offline_access")
	if openid {
		atHashSource := accessToken
		if ut.omitAtHash {
			atHashSource = ""
		}
		idToken, err := h.Minter.IDToken(ctx, IDTokenParams{
			TenantID: tenantID, Issuer: res.Issuer(), ClientID: c.ClientID, User: ut.user, Scopes: ut.scopes,
			Nonce: ut.nonce, SessionID: ut.sessionID, AuthTime: ut.authTime, AccessToken: atHashSource,
			Lifetime: time.Duration(c.IDTokenLifetime) * time.Second, CustomClaims: idClaims,
		})
		if err != nil {
			h.log().ErrorContext(ctx, "mint id token", "tenant", tenantID, "err", err)
			return nil, false, serverError()
		}
		resp.IdToken = &idToken
	}
	return resp, offline, nil
}

// operatorClaim is the tenant.OperatorClaim of a system-tenant access token
// for tenant.OperatorAudience: the operator's tenants. A user who is not an
// operator, or a client other than the console, gets access_denied, at every grant (refresh included), so
// removing an operator stops new tokens. Other tokens get no claim.
func (h *Handlers) operatorClaim(ctx context.Context, res tenant.Resolved, c *store.Client, ut userTokens) ([]string, *Error) {
	if !res.Tenant.Reserved || ut.rs == nil || ut.rs.Identifier != tenant.OperatorAudience {
		return nil, nil
	}
	// Operator tokens are bound to the console client.
	if c.ClientID != system.ConsoleClientID {
		return nil, accessDenied("only the zeroauthy console may request operator tokens")
	}
	op, err := h.Store.Operators().Get(ctx, res.Tenant.ID, ut.user.UserID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && len(op.Tenants) == 0) {
		return nil, accessDenied("the user is not a zeroauthy operator")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load operator", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	return slices.Clone(op.Tenants), nil
}
