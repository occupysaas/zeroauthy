package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// passwordlessOTPGrant exchanges a code sent by /passwordless/start (or the
// hosted page) for tokens. It follows the password grant: same MFA decision
// (MFA API audience rule included), post-login Actions, blocked users and
// token issuance. Refusals log fepotpft; success logs s (D-0060).
func (h *Handlers) passwordlessOTPGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (response *authapi.TokenResponse, failure *Error) {
	var eventConn *store.Connection
	var eventUserID string
	defer func() {
		code := "s"
		if failure != nil {
			if failure.Code == "mfa_required" {
				return
			}
			code = "fepotpft"
		}
		h.event(ctx, res, c, code, eventConn, eventUserID)
	}()
	otp := form.Get("otp")
	ctx = logscrub.WithCredentials(logscrub.WithValues(ctx, otp), otp)
	if h.Passwordless == nil {
		return nil, serverError()
	}
	if !c.IsFirstParty {
		return nil, unauthorizedClient("the passwordless OTP grant is not available to third-party applications")
	}
	realm, username := form.Get("realm"), form.Get("username")
	if realm == "" || username == "" || otp == "" {
		return nil, invalidRequest("realm, username and otp are required")
	}
	// P11: redirect_uri is optional; when sent it must be a callback.
	if ru := form.Get("redirect_uri"); ru != "" && !authz.AllowedURL(c.Callbacks, ru) {
		return nil, invalidRequest("redirect_uri is not an allowed callback URL")
	}
	tenantID := res.Tenant.ID
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, realm)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (!connrules.IsPasswordless(conn.Strategy) || conn.Strategy != realm || !containsString(conn.EnabledClients, c.ClientID))) {
		return nil, invalidRequest("the connection does not exist or is not enabled for this client")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load connection", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	ctx = events.Enrich(ctx, c, conn)
	eventConn = conn
	wrong := "Wrong email or verification code."
	if conn.Strategy == connrules.StrategySMS {
		wrong = "Wrong phone number or verification code."
	}
	ctx = passwordless.WithRequest(ctx, requestInfoFrom(ctx))
	user, err := h.Passwordless.VerifyCode(ctx, tenantID, c.ClientID, conn.Name, username, otp)
	var denied *identity.ErrSignupDenied
	var failed *identity.ErrSignupActionFailed
	switch {
	case errors.Is(err, passwordless.ErrInvalidCode):
		return nil, invalidGrant(wrong)
	case errors.Is(err, passwordless.ErrTooManyAttempts):
		return nil, tooManyRequests()
	case errors.Is(err, passwordless.ErrSignupDisabled):
		return nil, accessDenied("signups are disabled for this connection")
	case errors.Is(err, passwordless.ErrUserBlocked):
		return nil, accessDenied("user is blocked")
	case errors.As(err, &denied):
		return nil, accessDenied(denied.Description)
	case errors.As(err, &failed):
		return nil, serverError()
	case errors.Is(err, store.ErrPhoneUnavailable):
		return nil, &Error{Status: http.StatusNotImplemented, Code: "phone_unavailable", Description: "passwordless authentication is not available with this storage plugin"}
	case err != nil:
		h.log().ErrorContext(ctx, "passwordless grant", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	eventUserID = user.UserID
	ctx = logs.WithEvent(ctx, logs.Event{UserID: user.UserID, UserName: user.Name, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: "passwordless"})
	now := h.now().UTC()
	if err := h.Store.Users().RecordLogin(ctx, tenantID, user.UserID, now, httpx.CanonicalIP(clientIPFrom(ctx))); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", tenantID, "err", err)
	}
	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	if aud != "" && !h.isMFAAudience(ctx, tenantID, aud) {
		if _, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud); errors.Is(err, store.ErrNotFound) {
			return nil, accessDenied("unknown audience")
		} else if err != nil {
			return nil, serverError()
		}
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, aud)
	if oerr != nil {
		return nil, oerr
	}
	requested := strings.Fields(form.Get("scope"))
	d, oerr := h.decide(ctx, tenantID, access.Password, c, rs, userScopes(requested, rs, offlineAllowed(c, rs)))
	if oerr != nil {
		return nil, oerr
	}
	// The grant is realm-based like password-realm (D-0060 LR).
	eff, oerr := h.postLogin(ctx, res, c, loginFlow{user: user, connection: conn, rs: rs, protocol: actions.ProtocolResourceOwner, requested: requested, target: requested})
	if oerr != nil {
		return nil, oerr
	}
	before := d.Scopes
	if eff != nil && eff.Target != nil {
		if d, oerr = h.decide(ctx, tenantID, access.Password, c, rs, userScopes(eff.Target.Scopes, rs, offlineAllowed(c, rs))); oerr != nil {
			return nil, oerr
		}
	}
	scopes := d.Scopes
	ceiling := actions.CeilingOf(scopes, before)
	if required := h.passwordMFA(ctx, res, c, user, conn, aud, scopes, ceiling, eff, now); required != nil {
		return nil, required
	}
	resp, write, oerr := h.preparePasswordTokens(ctx, res, c, user, rs, lifetime, aud, scopes, ceiling, eff, now, time.Time{})
	if oerr != nil {
		return nil, oerr
	}
	version := user.Version
	err = h.mintTx(ctx, tenantID, user.UserID, &version, write)
	switch {
	case errors.Is(err, errUserBlocked):
		return nil, accessDenied("user is blocked")
	case errors.Is(err, errUserChanged):
		return nil, invalidGrant("the user is not allowed to sign in")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return resp, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
