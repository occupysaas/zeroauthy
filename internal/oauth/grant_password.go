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

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/protection"
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

// passwordGrant authenticates against the connection named by realm when
// the request carries one (as @auth0/auth0-auth-js sends it), otherwise
// against the tenant's default directory (Auth0 "Default Directory").
func (h *Handlers) passwordGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	if realm := form.Get("realm"); realm != "" {
		return h.resourceOwner(ctx, res, c, form, realm)
	}
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
	if !c.IsFirstParty {
		return nil, unauthorizedClient("the password grant is not available to third-party applications")
	}
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

	svc := h.protectionService()
	decision, err := svc.Begin(ctx, protection.Attempt{Tenant: res.Tenant, Connection: conn, Identifier: username, IP: clientIPFrom(ctx), Flow: "login"})
	if err != nil {
		h.log().ErrorContext(ctx, "protection admission", "err", err)
		return nil, serverError()
	}
	if !decision.Allowed {
		return nil, tooManyRequests()
	}

	required, err := svc.RequireChallenge(ctx, protection.Attempt{Tenant: res.Tenant, IP: clientIPFrom(ctx), Flow: "login"})
	if err != nil || required {
		if finishErr := svc.Finish(ctx, decision.Receipt, "refund"); finishErr != nil {
			return nil, serverError()
		}
		if err != nil {
			return nil, serverError()
		}
		return nil, &Error{Status: http.StatusUnauthorized, Code: "requires_verification", Description: "Complete verification using interactive web login."}
	}
	attemptID := secrets.RandomString(32)

	var breachErr error
	user, err := h.Database.LoginWithCheck(ctx, conn, username, password, func(ctx context.Context) error {
		breachErr = svc.CheckPasswordForUser(ctx, res.Tenant, "login", identity.EffectivePassword(conn, password), decision.SubjectID)
		return breachErr
	})
	outcome := protection.CredentialOutcome(err)
	if breachErr != nil {
		// Credentials were proved before the policy refusal.
		outcome = "success"
	}
	if finishErr := svc.Finish(ctx, decision.Receipt, outcome); finishErr != nil {
		h.log().ErrorContext(ctx, "protection completion", "err", finishErr)
		return nil, serverError()
	}
	riskErr := err
	if breachErr != nil {
		riskErr = breachErr
	}
	if protection.QualifyingFailure("login", riskErr) {
		if err := svc.RecordFailure(ctx, protection.Attempt{Tenant: res.Tenant, IP: clientIPFrom(ctx), Flow: "login"}, attemptID); err != nil {
			return nil, serverError()
		}
	}

	if breachErr != nil {
		if errors.Is(breachErr, protection.ErrPasswordLeaked) {
			return nil, &Error{Status: http.StatusUnauthorized, Code: "password_leaked", Description: protection.ErrPasswordLeaked.Error()}
		}
		return nil, &Error{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Description: protection.ErrBreachUnavailable.Error()}
	}
	var ue *identity.UnauthorizedError
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		h.log().InfoContext(ctx, "password grant failed", "tenant", tenantID, "client_id", c.ClientID, "connection", conn.Name)
		return nil, invalidGrant(wrongCredentials)
	case errors.Is(err, identity.ErrPasswordChangeRequired):
		h.log().InfoContext(ctx, "password grant: password change required", "tenant", tenantID, "client_id", c.ClientID, "connection", conn.Name)
		return nil, &Error{Status: http.StatusForbidden, Code: "invalid_grant", Description: "Password change required."}
	case errors.Is(err, identity.ErrUserBlocked):
		return nil, invalidGrant("user is blocked")
	case errors.As(err, &ue):
		// A custom database script refused the user; its message is meant
		// for the user (D-0023). The attempt still counts.
		return nil, &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Description: ue.Message}
	case err != nil:
		// A failure the script raised counts as a failed attempt; one that
		// kept the script from answering does not (D-0023).
		h.log().ErrorContext(ctx, "password grant", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	now := h.now().UTC()
	if err := h.Store.Users().RecordLogin(ctx, tenantID, user.UserID, now, httpx.CanonicalIP(clientIPFrom(ctx))); err != nil {
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
	d, oerr := h.decide(ctx, tenantID, access.Password, c, rs, userScopes(strings.Fields(form.Get("scope")), rs, offlineAllowed(c, rs)))
	if oerr != nil {
		return nil, oerr
	}
	scopes := d.Scopes
	resp, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes, authTime: now, grantType: "password",
	})
	if oerr != nil {
		return nil, oerr
	}
	var rt *store.RefreshToken
	var raw string
	if slices.Contains(scopes, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.Add(absolute)
		}
		rt, raw = h.newRefreshToken(c, tenantID, refreshGrant{
			familyID: "rtf_" + secrets.RandomString(32), userID: user.UserID,
			audience: aud, scopes: scopes, authTime: now, expiresAt: expiresAt,
		})
	}
	// The password was checked against the user at this Version. A reset,
	// block or session revocation since then refuses the grant.
	version := user.Version
	err = h.mintTx(ctx, tenantID, user.UserID, &version, func(tx store.Store) error {
		if rt == nil {
			return nil
		}
		return tx.RefreshTokens().Create(ctx, rt)
	})
	switch {
	case errors.Is(err, errUserBlocked):
		return nil, invalidGrant("user is blocked")
	case errors.Is(err, errUserChanged):
		return nil, invalidGrant("the user is not allowed to sign in")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt != nil {
		resp.RefreshToken = &raw
	}
	return resp, nil
}
