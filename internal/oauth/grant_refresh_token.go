package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var errOfflineAccessDisabled = errors.New("the API no longer allows offline access")

// refreshToken implements RFC 6749 §6 with rotation and reuse detection
// (RFC 9700 §4.14, D-0012).
func (h *Handlers) refreshToken(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (response *authapi.TokenResponse, failure *Error) {
	var eventConn *store.Connection
	var eventUserID string
	defer func() {
		if failure != nil && (failure.Code == "authorization_pending" || failure.Code == "slow_down") {
			return
		}
		code := "sertft"
		if failure != nil {
			code = "fertft"
		}
		h.event(ctx, res, c, code, eventConn, eventUserID)
	}()
	raw := form.Get("refresh_token")
	if raw == "" {
		return nil, invalidRequest("refresh_token is required")
	}
	tenantID := res.Tenant.ID
	now := h.now().UTC()
	// 400 by default (OIDCC-3.1.3.4); Auth0's 403 only when opted in.
	invalid := invalidGrant(unknownRefreshToken)
	if h.Auth0RefreshErrorStatus {
		invalid = forbiddenGrant(unknownRefreshToken)
	}

	rt, err := h.Store.RefreshTokens().GetByTokenHash(ctx, tenantID, secrets.HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if res.CheckOrigin(rt.Origin) != nil {
		// Bound to another public origin: never rotate or revoke it here.
		return nil, invalid
	}
	if rt.ClientID != c.ClientID {
		// Never rotate or revoke on behalf of a client that does not own the token.
		h.log().WarnContext(ctx, "refresh token presented by another client", "tenant", tenantID, "client_id", c.ClientID, "owner", rt.ClientID)
		return nil, invalid
	}
	// Ownership and origin are validated; retain token attribution before any
	// remaining rejection without loading its user or connection for logging.
	eventUserID = rt.UserID
	ctx = logs.WithEvent(ctx, logs.Event{UserID: rt.UserID, OrganizationID: rt.OrganizationID, ConnectionID: rt.OrganizationConnectionID})
	if rt.RevokedAt != nil {
		return nil, invalid
	}
	probe := store.CheckRefreshTokensIISupport(ctx, h.Store)
	if probe != nil && (!errors.Is(probe, store.ErrRefreshTokensIIUnavailable) || errors.Is(probe, store.ErrRefreshTokensIISupportLost)) {
		h.log().ErrorContext(ctx, "check refresh token store capability", "tenant", tenantID)
		return nil, serverError()
	}
	capable := probe == nil
	// Detect reuse before audience, scope, expiry and Actions can mask it.
	if rt.Rotating && rt.RotatedAt != nil {
		err = checkRefreshRotation(ctx, h.Store.RefreshTokens(), rt, c.RefreshToken, now, capable)
		switch {
		case errors.Is(err, store.ErrAlreadyUsed):
			h.logRefreshReuse(ctx, tenantID, c.ClientID, rt)
			return nil, invalid
		case errors.Is(err, store.ErrNotFound):
			return nil, invalid
		case err != nil:
			h.log().ErrorContext(ctx, "check refresh token reuse", "tenant", tenantID)
			return nil, serverError()
		}
	}
	if refreshExpired(rt, now) {
		return nil, invalid
	}
	audience := form.Get("audience")
	if audience == "" {
		audience = rt.Audience
	}
	cross := audience != rt.Audience
	if cross && len(c.RefreshToken.Policies) == 0 {
		return nil, invalidRequest("audience does not match the refresh token")
	}
	source, lifetime, oerr := h.audienceFor(ctx, tenantID, rt.Audience)
	if oerr != nil {
		return nil, oerr
	}
	offlineGrant := rt.Access != "online"
	var onlineSess *store.LoginSession
	if !offlineGrant {
		if !capable {
			return nil, serverError()
		}
		onlineSess, err = onlineSession(ctx, h.Store, res, rt.UserID, rt.SessionID, now)
		if err != nil && !errors.Is(err, errOnlineSession) {
			return nil, serverError()
		}
		if errors.Is(err, errOnlineSession) || !onlineEligible(c, source, onlineSess) {
			return nil, invalidGrant("the online session is no longer eligible")
		}
		if failure := onlineProof(ctx, c); failure != nil {
			return nil, failure
		}
	}
	if offlineGrant && source != nil && !source.AllowOfflineAccess {
		return nil, invalidGrant(errOfflineAccessDisabled.Error())
	}
	rs := source
	var mrrt *mrrtExchange
	requested := strings.Fields(form.Get("scope"))
	scopes := rt.Scopes
	if len(c.RefreshToken.Policies) > 0 {
		if !capable {
			return nil, invalidRequest("refresh token policies require storage support")
		}
		mrrt = &mrrtExchange{family: rt, audience: audience, managementAudience: tenant.ManagementAPIIdentifier(res.Tenant, h.BaseDomain), requested: requested}
		if cross {
			rs, err = h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, audience)
			if errors.Is(err, store.ErrNotFound) {
				return nil, invalidRequest(disallowedMRRTAudience)
			}
			if err != nil {
				return nil, serverError()
			}
		}
		scopes, oerr = mrrt.resolve(ctx, h, h.Store, c, rs)
		if oerr != nil {
			return nil, oerr
		}
	} else if requested := userScopes(requested, rs, true); len(requested) > 0 {
		// Plain refresh can only narrow scopes that issuance recognizes.
		for _, s := range requested {
			if !slices.Contains(rt.Scopes, s) {
				return nil, invalidScope(fmt.Sprintf("scope %q was not granted to this refresh token", s))
			}
		}
		scopes = requested
	}

	user, oerr := h.activeUserBlocked(ctx, tenantID, rt.UserID, "user is blocked")
	if oerr != nil {
		return nil, oerr
	}
	eventConn = eventConnection(user, rt.OrganizationConnectionID)
	ctx = logs.WithEvent(ctx, logs.Event{OrganizationID: rt.OrganizationID, UserID: user.UserID, UserName: user.Name, Connection: eventConn.Name, ConnectionID: eventConn.ID, Strategy: eventConn.Strategy})
	org, oerr := h.organizationForToken(ctx, tenantID, user.UserID, rt.OrganizationID, rt.OrganizationConnectionID, c)
	if oerr != nil {
		return nil, oerr
	}
	// Re-filter in case the API dropped a scope since the token was issued.
	scopes = userScopes(scopes, rs, true)
	d, oerr := h.decide(ctx, tenantID, access.Refresh, c, rs, scopes)
	if oerr != nil {
		return nil, oerr
	}
	// The post-login flow runs again (spec §7), after the reuse checks
	// above, so a replayed token runs no Action. Its claims and its
	// target-scope and addScope additions are never stored with the
	// family (whose ceiling never grows): the flow must add them again.
	// Target edits are filtered by API definition, policy and RBAC.
	// event.session is the family's session while it is live, offline
	// families included (Plan 40).
	eventSess := onlineSess
	if eventSess == nil && rt.SessionID != "" {
		if s, e := h.Store.Sessions().Get(ctx, tenantID, rt.SessionID); e == nil && s.UserID == rt.UserID && h.now().Before(s.ExpiresAt) && h.now().Before(s.IdleExpiresAt) {
			eventSess = s
		}
	}
	eff, oerr := h.postLogin(ctx, res, c, loginFlow{organizationID: rt.OrganizationID, connectionID: rt.OrganizationConnectionID, session: eventSess, refreshToken: rt, user: user, userConnection: true, rs: rs, protocol: actions.ProtocolRefreshToken,
		requested: d.Scopes, target: d.Scopes})
	if oerr != nil {
		return nil, oerr
	}
	before := d.Scopes
	if eff != nil && eff.Target != nil {
		target := eff.Target.Scopes
		if mrrt != nil {
			target = actions.CeilingOf(target, before)
		}
		target, oerr := h.consentedAdditions(ctx, tenantID, c, user.UserID, rs, before, target)
		if oerr != nil {
			return nil, oerr
		}
		if d, oerr = h.decide(ctx, tenantID, access.Refresh, c, rs, userScopes(target, rs, true)); oerr != nil {
			return nil, oerr
		}
	}
	scopes = d.Scopes
	resp, offline, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		online: !offlineGrant, mrrt: mrrt, organization: org, user: user, rs: rs, lifetime: lifetime, scopes: scopes,
		userInfoClaims: rt.UserInfoClaims, acr: rt.ACR, sessionID: rt.SessionID, authTime: rt.AuthTime, refreshSessionMFA: true, effects: eff,
	})
	if oerr != nil {
		return nil, oerr
	}
	// When the flow removed offline_access (a target or accessToken
	// removal), the exchange ends without a new refresh token, as at the
	// other grants: the token is neither rotated nor extended. A request
	// that narrowed offline_access away itself keeps the old behaviour.
	keep := offline || !slices.Contains(before, "offline_access")

	// The minted tokens are only sent once the refresh token is consumed,
	// in a transaction that checks the user is still at the Version loaded
	// above. Preserve the family revocation on ErrAlreadyUsed while rolling
	// back ordinary write failures.
	version := user.Version
	var currentClient *store.Client
	var reused bool
	var nextRaw string
	err = h.mintCheckedTx(ctx, tenantID, rt.UserID, &version, func(tx store.Store) error {
		var err error
		currentClient, err = clientForTokenOrganization(ctx, tx, tenantID, user.UserID, rt.OrganizationID, rt.OrganizationConnectionID, c.ClientID)
		if err != nil {
			return err
		}
		if offlineGrant && !slices.Contains(currentClient.GrantTypes, "refresh_token") {
			return invalidRequest("the refresh grant is no longer enabled")
		}
		if offlineGrant && source != nil {
			// The family remains bound to its issuing API even when the access
			// token is for another audience.
			currentAPI, err := tx.ResourceServers().GetByIdentifier(ctx, tenantID, rt.Audience)
			if err != nil {
				return err
			}
			if !currentAPI.AllowOfflineAccess {
				return errOfflineAccessDisabled
			}
		}
		if mrrt != nil {
			return mrrt.checkMint(ctx, h, tx, currentClient)
		}
		if len(currentClient.RefreshToken.Policies) > 0 {
			// The signed plain-refresh response did not apply the new MRRT
			// ceiling to Action edits. Leave the presentation live for retry.
			return invalidRequest("refresh token policies changed during refresh")
		}
		return nil
	}, func(tx store.Store) error {
		if rt.SessionID != "" {
			session, e := tx.Sessions().GetForUpdate(ctx, tenantID, rt.SessionID)
			if e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
			if e == nil && session.UserID == rt.UserID && (session.ExpiresAt.IsZero() || h.now().Before(session.ExpiresAt)) && (session.IdleExpiresAt.IsZero() || h.now().Before(session.IdleExpiresAt)) {
				var custom map[string]any
				if eff != nil {
					custom = eff.IDClaims
				}
				filtered, e := actions.FilterClaims(actions.ClaimIDToken, nil, custom, false)
				if e != nil {
					return e
				}
				raw, e := json.Marshal(filtered)
				if e != nil {
					return e
				}
				if _, e = store.SetSessionClaims(ctx, tx, tenantID, rt.SessionID, c.ClientID, string(raw)); e != nil {
					return e
				}
			}
		}
		if !offlineGrant {
			return h.finishOnline(ctx, tx, res, currentClient, rt)
		}
		var writeErr error
		nextRaw, writeErr = finishRefresh(ctx, tx.RefreshTokens(), rt, currentClient, res.Origin(), h.now().UTC(), keep, capable)
		if errors.Is(writeErr, store.ErrAlreadyUsed) {
			reused = true
			return nil
		}
		if writeErr != nil {
			return writeErr
		}
		if capable {
			if err := h.recordRefreshExchange(ctx, tx.RefreshTokens(), rt, nextRaw); err != nil {
				return err
			}
		}
		if eff != nil && eff.RefreshToken != nil {
			live := rt
			if nextRaw != "" {
				if live, writeErr = tx.RefreshTokens().GetByTokenHash(ctx, tenantID, secrets.HashToken(nextRaw)); writeErr != nil {
					return writeErr
				}
			} else if live, writeErr = tx.RefreshTokens().Get(ctx, tenantID, rt.ID); writeErr != nil {
				return writeErr
			}
			return applyRefreshTokenEffects(ctx, tx, tenantID, live, eff.RefreshToken)
		}
		return nil
	})
	var policyErr *Error
	if errors.As(err, &policyErr) {
		return nil, policyErr
	}
	if errors.Is(err, errOnlineSession) {
		return nil, invalidGrant("the online session is no longer eligible")
	}
	if errors.Is(err, errOfflineAccessDisabled) {
		return nil, invalidGrant(errOfflineAccessDisabled.Error())
	}
	if errors.Is(err, errOrganizationGrant) {
		return nil, invalidGrant("the organization grant is no longer eligible")
	}
	if errors.Is(err, errUserBlocked) {
		return nil, invalidGrant("user is blocked")
	}
	if errors.Is(err, errUserChanged) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	switch {
	case err == nil && reused:
		h.logRefreshReuse(ctx, tenantID, c.ClientID, rt)
		return nil, invalid
	case errors.Is(err, store.ErrNotFound):
		return nil, invalid
	case err != nil:
		h.log().ErrorContext(ctx, "complete refresh exchange", "tenant", tenantID)
		return nil, serverError()
	}
	if nextRaw != "" {
		resp.RefreshToken = &nextRaw
	}
	if cross {
		// The response also describes credentials supplied by the original
		// identity and offline grants. The signed token contains only the
		// second API's authorized permissions.
		responseScopes := slices.Clone(mrrt.issued)
		if resp.IdToken != nil && slices.Contains(requested, "openid") {
			responseScopes = append(responseScopes, "openid")
		}
		if offlineGrant && keep && slices.Contains(rt.Scopes, "offline_access") && slices.Contains(requested, "offline_access") {
			responseScopes = append(responseScopes, "offline_access")
		}
		scope := strings.Join(responseScopes, " ")
		resp.Scope = &scope
	}
	if user != nil {
		eventUserID = user.UserID
	}
	return resp, nil
}

func (h *Handlers) logRefreshReuse(ctx context.Context, tenantID, clientID string, rt *store.RefreshToken) {
	logs.RecordEvent(ctx, h.Recorder, logs.Event{TenantID: tenantID, Type: "ferrt", ClientID: clientID, UserID: rt.UserID, OrganizationID: rt.OrganizationID})
	h.log().WarnContext(ctx, "refresh token reuse detected; family revoked",
		"tenant", tenantID, "client_id", clientID, "user_id", rt.UserID, "family", rt.FamilyID)
}
