package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// GrantPasswordRealm is Auth0's documented extension grant for the
// resource owner password flow with an explicit connection (realm).
const GrantPasswordRealm = "http://auth0.com/oauth/grant-type/password-realm"

const wrongCredentials = "wrong email/username or password"

type clientIPKey struct{}

func withClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func clientIPFrom(ctx context.Context) string { s, _ := ctx.Value(clientIPKey{}).(string); return s }

// endUserIP is the address used for throttling. auth0-forwarded-for lets a
// confidential server-side client pass its end user's IP; a public client
// could forge it, so for those the request's own address is used. A value
// that is not an IP address is ignored, so it cannot be used to mint fresh
// throttle keys.
func (h *Handlers) endUserIP(r *http.Request, c *store.Client) string {
	if c.TokenEndpointAuthMethod != store.AuthMethodNone {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("auth0-forwarded-for"))); ip != nil {
			return ip.String()
		}
	}
	return httpx.ClientIP(r, h.TrustProxyHeaders)
}

// passwordGrant authenticates against the tenant's default directory
// (Auth0 "Default Directory").
func (h *Handlers) passwordGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	if res.Tenant.DefaultDirectory == "" {
		return nil, invalidRequest("the tenant has no default directory; use the password-realm grant with realm")
	}
	return h.resourceOwner(ctx, res, c, form, res.Tenant.DefaultDirectory)
}

func (h *Handlers) passwordRealmGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	realm := form.Get("realm")
	if realm == "" {
		return nil, invalidRequest("realm is required")
	}
	return h.resourceOwner(ctx, res, c, form, realm)
}

// resourceOwner implements RFC 6749 §4.3 against one database connection.
func (h *Handlers) resourceOwner(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values, connName string) (*authapi.TokenResponse, *Error) {
	tenantID := res.Tenant.ID
	username, password := form.Get("username"), form.Get("password")
	if username == "" || password == "" {
		return nil, invalidRequest("username and password are required")
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, connName)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (conn.Strategy != store.StrategyDatabase || !slices.Contains(conn.EnabledClients, c.ClientID))) {
		return nil, invalidRequest("the connection does not exist or is not enabled for this client")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load connection", "tenant", tenantID, "err", err)
		return nil, serverError()
	}

	userKey := identity.UserThrottleKey(tenantID, conn.Name, username)
	ipKey := identity.IPThrottleKey(tenantID, clientIPFrom(ctx))
	if !h.IPThrottle.Attempt(ipKey) || !h.UserThrottle.Attempt(userKey) {
		return nil, tooManyRequests()
	}
	user, err := h.Database.Login(ctx, conn, username, password)
	var ue *identity.UnauthorizedError
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.log().InfoContext(ctx, "password grant failed", "tenant", tenantID, "client_id", c.ClientID, "connection", conn.Name)
		return nil, invalidGrant(wrongCredentials)
	case errors.Is(err, identity.ErrUserBlocked):
		h.UserThrottle.Success(userKey)
		h.IPThrottle.Refund(ipKey)
		return nil, invalidGrant("the user is blocked")
	case errors.As(err, &ue):
		// A custom database script refused the user; its message is meant
		// for the user (D-0023). The attempt still counts.
		return nil, &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Description: ue.Message}
	case err != nil:
		// A failure the script raised counts as a failed attempt; one that
		// kept the script from answering does not (D-0023).
		if !identity.ScriptRaised(err) {
			h.UserThrottle.Refund(userKey)
			h.IPThrottle.Refund(ipKey)
		}
		h.log().ErrorContext(ctx, "password grant", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	h.UserThrottle.Success(userKey)
	h.IPThrottle.Refund(ipKey)
	now := h.now().UTC()
	if err := h.Store.Users().RecordLogin(ctx, tenantID, user.UserID, now); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", tenantID, "err", err)
	}

	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	if aud != "" {
		// Like client_credentials: an unknown API is access_denied, not a bad grant.
		if _, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud); errors.Is(err, store.ErrNotFound) {
			return nil, accessDenied("unknown audience")
		} else if err != nil {
			h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, aud)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(strings.Fields(form.Get("scope")), rs, offlineAllowed(c, rs))
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes, authTime: now, grantType: "password",
	})
	if oerr != nil {
		return nil, oerr
	}
	if slices.Contains(scopes, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.Add(absolute)
		}
		rt, raw := h.newRefreshToken(c, tenantID, refreshGrant{
			familyID: "rtf_" + secrets.RandomString(32), userID: user.UserID,
			audience: aud, scopes: scopes, authTime: now, expiresAt: expiresAt,
		})
		if err := h.Store.RefreshTokens().Create(ctx, rt); err != nil {
			h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
		resp.RefreshToken = &raw
	}
	return resp, nil
}
