package oauth

import (
	"time"

	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type requestInfoKey struct{}

// withRequestInfo records the token request for event.request. The body is
// the request's parameters; the engine drops credentials from it.
func withRequestInfo(ctx context.Context, r *http.Request, ip string, form url.Values) context.Context {
	body := make(map[string]any, len(form))
	for k := range form {
		body[k] = form.Get(k)
	}
	lang, _, _ := strings.Cut(r.Header.Get("Accept-Language"), ",")
	lang, _, _ = strings.Cut(lang, ";")
	return context.WithValue(ctx, requestInfoKey{}, actions.RequestInfo{
		SecurityContext: actions.SecurityContextFrom(ctx), CorrelationID: actions.CorrelationID(r),
		IP: ip, Hostname: r.Host, Method: r.Method, UserAgent: r.UserAgent(), Language: strings.TrimSpace(lang),
		Query: map[string]any{}, Body: body,
	})
}

func requestInfoFrom(ctx context.Context) actions.RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(actions.RequestInfo)
	return ri
}

// loginFlow is a token-endpoint grant that runs the post-login flow.
type loginFlow struct {
	pendingMembership bool
	session           *store.LoginSession
	refreshToken      *store.RefreshToken
	organizationID    string
	connectionID      string // original connection of an organization refresh family
	user              *store.User
	connection        *store.Connection // nil when unknown
	// userConnection resolves the pinned connectionID, or the first identity
	// for individual grants, only when Actions are bound.
	userConnection bool
	rs             *store.ResourceServer
	protocol       string
	requested      []string
	target         []string
}

// postLogin runs the tenant's post-login flow for a token-endpoint grant,
// where api.redirect.canRedirect() is false. A denial is 403 with the
// denial's code and reason (D-0053); a failed flow is server_error with a
// generic description (the execution ID is only logged, by the engine).
// Without an engine it returns no effects.
func (h *Handlers) postLogin(ctx context.Context, res tenant.Resolved, c *store.Client, f loginFlow) (*actions.Effects, *Error) {
	if h.Actions == nil {
		return nil, nil
	}
	in := actions.PostLoginInput{
		PendingMembership: f.pendingMembership, Session: f.session, RefreshToken: f.refreshToken, OrganizationID: f.organizationID, Tenant: res, Client: c, User: f.user, Connection: f.connection, Request: requestInfoFrom(ctx),
		Protocol: f.protocol, RequestedScopes: f.requested, TargetScopes: f.target, ResourceServer: f.rs,
	}
	if f.userConnection {
		in.Prepare = func(ctx context.Context, in *actions.PostLoginInput) error {
			var conn *store.Connection
			var err error
			if f.connectionID != "" {
				conn, err = h.Store.Connections().Get(ctx, res.Tenant.ID, f.connectionID)
			} else {
				conn, err = h.userConnection(ctx, res.Tenant.ID, in.User)
			}
			in.Connection = conn
			return err
		}
	}
	result, err := h.Actions.PostLogin(ctx, in)
	if result != nil {
		logs.AddExecution(ctx, result.ExecutionID)
	}
	var executionFailure *actions.ErrFlow
	if errors.As(err, &executionFailure) {
		logs.AddExecution(ctx, executionFailure.ExecutionID)
	}
	if err != nil {
		var fe *actions.ErrFlow
		if !errors.As(err, &fe) {
			h.log().ErrorContext(ctx, "run post-login Actions", "tenant", res.Tenant.ID, "err", err)
		}
		return nil, serverError()
	}
	if result.Effects.RefreshTokenRevoke && f.refreshToken != nil {
		var e error
		if f.refreshToken.Access == "online" {
			e = h.endOnlineSession(ctx, res, f.refreshToken)
		} else {
			e = h.Store.WithTx(ctx, func(tx store.Store) error {
				if _, e := tx.Users().GetForUpdate(ctx, res.Tenant.ID, f.refreshToken.UserID); e != nil {
					return e
				}
				return tx.RefreshTokens().RevokeFamily(ctx, res.Tenant.ID, f.refreshToken.FamilyID, h.now().UTC())
			})
		}
		if e != nil {
			return nil, serverError()
		}
		return nil, invalidGrant("the refresh token was revoked")
	}

	if se := result.Effects.Session; se != nil && se.Revoke != nil {
		// api.session.revoke on a token grant ends the grant's session (Plan 40).
		if f.session != nil {
			if e := h.revokeActionSession(ctx, res, f.session, se.Revoke.PreserveRefreshTokens); e != nil {
				return nil, serverError()
			}
		}
		reason := se.Revoke.Reason
		if reason == "" {
			reason = "the session was revoked"
		}
		return nil, &Error{Status: http.StatusForbidden, Code: "access_denied", Description: reason}
	}
	if d := result.Denied; d != nil {
		return nil, &Error{Status: http.StatusForbidden, Code: d.Code, Description: d.Reason}
	}
	if result.Effects.PrimaryUserID != "" {
		// Account linking from an Action needs the browser flow's session
		// (Plan 40); a token grant is refused rather than issuing for the
		// secondary.
		return nil, &Error{Status: http.StatusForbidden, Code: "access_denied", Description: "setPrimaryUser is not supported on this grant"}
	}
	if se := result.Effects.Session; se != nil && f.session != nil && f.refreshToken == nil {
		if e := h.applyActionSession(ctx, res, f.session, se); e != nil {
			return nil, serverError()
		}
	}
	return &result.Effects, nil
}

// revokeActionSession ends sess for api.session.revoke on a token grant: its
// refresh tokens are revoked unless preserved, the user's version bumps, the
// session is deleted and back-channel logout is queued, in one transaction.
func (h *Handlers) revokeActionSession(ctx context.Context, res tenant.Resolved, sess *store.LoginSession, preserve bool) error {
	return session.RevokeFromAction(ctx, h.Store, sess, preserve, h.now(), func(ctx context.Context, tx store.Store, current *store.LoginSession) error {
		if h.Logout != nil {
			return h.Logout.WithStore(tx).SessionsEnded(ctx, res.Tenant.ID, []*store.LoginSession{current}, logout.SessionRevoked)
		}
		return nil
	})
}

// applyActionSession applies api.session setters and metadata calls on a
// token grant's session: expiries only shorten (LR40-3); no cookie exists
// here, so the cookie mode is stored for the next browser request.
func (h *Handlers) applyActionSession(ctx context.Context, res tenant.Resolved, sess *store.LoginSession, se *actions.SessionEffects) error {
	tid := res.Tenant.ID
	return h.Store.WithTx(ctx, func(tx store.Store) error {
		current, err := tx.Sessions().GetForUpdate(ctx, tid, sess.ID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(se.Metadata) > 0 {
			md, err := actions.ApplyMetadataOps(current.Metadata, se.Metadata)
			if err != nil {
				return err
			}
			if current, err = tx.Sessions().UpdateMetadata(ctx, tid, sess.ID, md); err != nil {
				return err
			}
		}
		if se.ExpiresAt == nil && se.IdleExpiresAt == nil && se.CookieMode == "" {
			return nil
		}
		exp, idle := shortenLimits(current.ExpiresAt, current.IdleExpiresAt, se.ExpiresAt, se.IdleExpiresAt)
		mode := current.CookieMode
		if se.CookieMode != "" {
			mode = se.CookieMode
		}
		next := *current
		next.ExpiresAt, next.IdleExpiresAt, next.CookieMode = exp, idle, mode
		session.CapActionLimits(res.Tenant, &next, sess, h.now())
		_, err = store.SetSessionLimits(ctx, tx, tid, sess.ID, next.ExpiresAt, next.IdleExpiresAt, next.CookieMode)
		return err
	})
}

// shortenLimits caps requested absolute and idle expiries by the current
// ones (zero current meaning never) and keeps idle within absolute.
func shortenLimits(curAbs, curIdle time.Time, reqAbs, reqIdle *time.Time) (time.Time, time.Time) {
	abs, idle := curAbs, curIdle
	if reqAbs != nil && (abs.IsZero() || reqAbs.Before(abs)) {
		abs = *reqAbs
	}
	if reqIdle != nil && (idle.IsZero() || reqIdle.Before(idle)) {
		idle = *reqIdle
	}
	if !abs.IsZero() && !idle.IsZero() && idle.After(abs) {
		idle = abs
	}
	return abs, idle
}

// applyRefreshTokenEffects applies api.refreshToken setters and metadata to
// the live token of the family (the successor when it rotated) inside the
// mint transaction.
func applyRefreshTokenEffects(ctx context.Context, tx store.Store, tid string, live *store.RefreshToken, re *actions.RefreshTokenEffects) error {
	if re == nil || live == nil {
		return nil
	}
	if len(re.Metadata) > 0 {
		md, err := actions.ApplyMetadataOps(live.Metadata, re.Metadata)
		if err != nil {
			return err
		}
		if live, err = tx.RefreshTokens().UpdateMetadata(ctx, tid, live.ID, md); err != nil {
			return err
		}
	}
	if re.ExpiresAt == nil && re.IdleExpiresAt == nil {
		return nil
	}
	exp, idle := shortenLimits(live.ExpiresAt, live.IdleExpiresAt, re.ExpiresAt, re.IdleExpiresAt)
	_, err := store.SetRefreshTokenLimits(ctx, tx, tid, live.ID, exp, idle)
	return err
}

// targetScopes is scopes after the flow's transaction target-scope edits,
// kept within allowed when it is given (a client grant's scopes). The
// result is still filtered by API definition, client policy and RBAC.
func targetScopes(eff *actions.Effects, scopes, allowed []string) []string {
	if eff == nil || eff.Target == nil {
		return scopes
	}
	out := []string{}
	for _, s := range eff.Target.Scopes {
		if allowed == nil || slices.Contains(allowed, s) {
			out = append(out, s)
		}
	}
	return out
}

// refreshCeiling is the scope set a refresh family started by a code or
// device approval stores: the authorized set before the Actions'
// target-scope edits (spec §7), which the flow recorded when it differs
// from the issued scopes.
func refreshCeiling(eff *actions.Effects, scopes []string, rs *store.ResourceServer, offline bool) []string {
	if eff == nil || eff.Ceiling == nil {
		return scopes
	}
	return userScopes(eff.Ceiling, rs, offline)
}

// userConnection is the connection of the user's first identity, for
// event.connection; nil when it cannot be found.
func (h *Handlers) userConnection(ctx context.Context, tenantID string, u *store.User) (*store.Connection, error) {
	if u == nil || len(u.Identities) == 0 {
		return nil, nil
	}
	conn, err := h.Store.Connections().GetByName(ctx, tenantID, u.Identities[0].Connection)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return conn, err
}

// openEffects opens the post-login effects sealed onto a code or device
// approval; a blob that does not open fails closed.
func (h *Handlers) openEffects(ctx context.Context, tenantID, purpose, hash string, sealed []byte) (*actions.Effects, *Error) {
	if len(sealed) == 0 {
		return nil, nil
	}
	eff, err := actions.OpenEffects(h.Wrapper, tenantID, purpose, sealed, hash)
	if err != nil {
		h.log().ErrorContext(ctx, "open Action effects", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	return eff, nil
}

// consentedAdditions limits a refresh flow's target scopes for a client
// that goes through consent: the refresh grant has no consent step, so
// scopes the Actions add beyond before (the scopes authorized before the
// flow) are kept only when the user's grant for the audience holds them;
// others are dropped silently, as policy-filtered scopes are. First-party
// clients that skip consent are not limited.
func (h *Handlers) consentedAdditions(ctx context.Context, tenantID string, c *store.Client, userID string, rs *store.ResourceServer, before, target []string) ([]string, *Error) {
	return h.consentedAdditionsWithStore(ctx, h.Store, tenantID, c, userID, rs, before, target)
}

func (h *Handlers) consentedAdditionsWithStore(ctx context.Context, st store.Store, tenantID string, c *store.Client, userID string, rs *store.ResourceServer, before, target []string) ([]string, *Error) {
	var added []string
	for _, s := range target {
		if !slices.Contains(before, s) {
			added = append(added, s)
		}
	}
	if len(added) == 0 || !access.ConsentApplies(c, rs) {
		return target, nil
	}
	audience := ""
	if rs != nil {
		audience = rs.Identifier
	}
	if audience == "" {
		return actions.CeilingOf(target, before), nil
	}
	var granted []string
	g, err := st.UserGrants().Find(ctx, tenantID, c.ClientID, userID, audience)
	switch {
	case err == nil:
		granted = g.Scopes
	case !errors.Is(err, store.ErrNotFound):
		h.log().ErrorContext(ctx, "load user grant", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	out := []string{}
	for _, s := range target {
		if slices.Contains(before, s) || slices.Contains(granted, s) {
			out = append(out, s)
		}
	}
	return out, nil
}
