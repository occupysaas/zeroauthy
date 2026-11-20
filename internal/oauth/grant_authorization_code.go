package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// authorizationCode implements RFC 6749 §4.1.3 with RFC 7636 PKCE.
func (h *Handlers) authorizationCode(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (response *authapi.TokenResponse, failure *Error) {
	var eventConn *store.Connection
	var eventUserID string
	defer func() {
		if failure != nil && (failure.Code == "authorization_pending" || failure.Code == "slow_down") {
			return
		}
		code := "seacft"
		if failure != nil {
			code = "feacft"
		}
		h.event(ctx, res, c, code, eventConn, eventUserID)
	}()
	code := form.Get("code")
	if code == "" {
		return nil, invalidRequest("code is required")
	}
	tenantID := res.Tenant.ID
	now := h.now()
	// Only the owning client on the issuing origin may consume a code or
	// trigger replay revocation of its refresh-token family.
	hash := secrets.HashToken(code)
	pre, err := h.Store.AuthCodes().Get(ctx, tenantID, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalidGrant("invalid authorization code")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load authorization code origin", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if res.CheckOrigin(pre.Origin) != nil || pre.ClientID != c.ClientID {
		return nil, invalidGrant("invalid authorization code")
	}
	ac, err := h.claimAuthorizationCode(ctx, res, c.ClientID, hash, now)
	if err != nil {
		var failure *Error
		switch {
		case errors.As(err, &failure):
			return nil, failure
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrAlreadyUsed):
			return nil, invalidGrant("invalid authorization code")
		default:
			h.log().ErrorContext(ctx, "claim authorization code", "tenant", tenantID, "err", err)
			return nil, serverError()
		}
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

	eventUserID = ac.UserID
	user, oerr := h.activeUser(ctx, tenantID, ac.UserID)
	if oerr != nil {
		return nil, oerr
	}
	eventConn = eventConnection(user, ac.OrganizationConnectionID)
	ctx = logs.WithEvent(ctx, logs.Event{OrganizationID: ac.OrganizationID, UserID: user.UserID, UserName: user.Name, Connection: eventConn.Name, ConnectionID: eventConn.ID, Strategy: eventConn.Strategy})
	org, oerr := h.organizationForToken(ctx, tenantID, user.UserID, ac.OrganizationID, ac.OrganizationConnectionID, c)
	if oerr != nil {
		return nil, oerr
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, ac.Audience)
	if oerr != nil {
		return nil, oerr
	}
	// The post-login flow ran at /authorize; its effects travel sealed.
	eff, oerr := h.openEffects(ctx, tenantID, actions.SealCode, ac.CodeHash, ac.ActionEffects)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(ac.Scopes, rs, offlineAllowed(c, rs))
	var onlineSess *store.LoginSession
	online := false
	if slices.Contains(ac.Scopes, "online_access") {
		if store.CheckRefreshTokensIISupport(ctx, h.Store) != nil {
			return nil, serverError()
		}
		onlineSess, err = onlineSession(ctx, h.Store, res, user.UserID, ac.SessionID, h.now().UTC())
		if err != nil && !errors.Is(err, errOnlineSession) {
			return nil, serverError()
		}
		online = onlineEligible(c, rs, onlineSess)
		if online {
			if failure := onlineProof(ctx, c); failure != nil {
				return nil, failure
			}
		}
	}
	if !online {
		scopes = slices.DeleteFunc(scopes, func(s string) bool { return s == "online_access" })
	}
	resp, offline, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		online: online, organization: org, user: user, rs: rs, lifetime: lifetime, scopes: scopes,
		nonce: ac.Nonce, sessionID: ac.SessionID, authTime: ac.AuthTime, mfaAt: ac.MFAAt, effects: eff,
	})
	if oerr != nil {
		return nil, oerr
	}
	var rt *store.RefreshToken
	var raw string
	ceiling := refreshCeiling(eff, scopes, rs, offlineAllowed(c, rs))
	if offline && slices.Contains(ceiling, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.UTC().Add(absolute)
		}
		rt, raw = h.newRefreshToken(ctx, c, tenantID, refreshGrant{

			organizationID: ac.OrganizationID, organizationConnectionID: ac.OrganizationConnectionID,
			origin:   res.Origin(),
			familyID: familyForCode(ac.CodeHash), userID: user.UserID, sessionID: ac.SessionID,
			audience: ac.Audience, scopes: ceiling, authTime: ac.AuthTime, expiresAt: expiresAt,
		})
	}
	if online && resp.Scope != nil && slices.Contains(strings.Fields(*resp.Scope), "online_access") && slices.Contains(ceiling, "online_access") {
		rt, raw = h.newRefreshToken(ctx, c, tenantID, refreshGrant{origin: res.Origin(), organizationID: ac.OrganizationID, organizationConnectionID: ac.OrganizationConnectionID, familyID: familyForCode(ac.CodeHash), userID: user.UserID, sessionID: ac.SessionID, audience: ac.Audience, scopes: ceiling, authTime: ac.AuthTime})
		rt.Access = "online"
		rt.Rotating = false
		rt.ExpiresAt = onlineSess.ExpiresAt
		rt.IdleExpiresAt = time.Time{}
	}
	// Compare the revision sampled by this redemption, after the earlier
	// browser authorization or device approval.
	replayed := false
	err = h.mintCheckedTx(ctx, tenantID, user.UserID, &user.Version, func(tx store.Store) error {
		return checkTokenOrganization(ctx, tx, tenantID, user.UserID, ac.OrganizationID, ac.OrganizationConnectionID, c.ClientID)
	}, func(tx store.Store) error {
		if rt != nil && rt.Access == "online" {
			currentClient, e := tx.Clients().Get(ctx, tenantID, c.ClientID)
			if e != nil {
				return e
			}
			currentAPI, e := tx.ResourceServers().GetByIdentifier(ctx, tenantID, ac.Audience)
			if e != nil {
				return e
			}
			currentSess, _, e := h.lockedOnlineSession(ctx, tx, res, user.UserID, ac.SessionID)
			if e != nil {
				return e
			}
			if !onlineEligible(currentClient, currentAPI, currentSess) {
				return errOnlineSession
			}
			if failure := onlineProof(ctx, currentClient); failure != nil {
				return failure
			}
			rt.ExpiresAt = currentSess.ExpiresAt
		}
		if rt != nil {
			if err := createInitialRefresh(ctx, tx, rt); err != nil {
				return err
			}
		}
		// An authorization-time key is permanent. A key reserved by the
		// initial claim is released only if this exchange issued no bound RT.
		if key := proofJKT(ctx); key != "" && ac.DPoPJKT == "" && (rt == nil || rt.DPoPJKT == "") {
			if err := tx.AuthCodes().SetRedemptionBinding(ctx, tenantID, ac.CodeHash, key, ""); err != nil {
				return err
			}
		}
		if rt == nil {
			return nil
		}
		latest, err := tx.AuthCodes().Get(ctx, tenantID, ac.CodeHash)
		if err != nil {
			return err
		}
		replayed = latest.ReplayedAt != nil
		if replayed {
			return tx.RefreshTokens().RevokeFamily(ctx, tenantID, rt.FamilyID, now)
		}
		return nil
	})
	switch {
	case errors.Is(err, errOrganizationGrant):
		return nil, invalidGrant("the organization grant is no longer eligible")
	case errors.Is(err, errOnlineSession):
		return nil, invalidGrant("the online session is no longer eligible")
	case errors.Is(err, errUserChanged):
		return nil, invalidGrant("the user is not allowed to sign in")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if replayed {
		return nil, invalidGrant("invalid authorization code")
	}
	if rt != nil {
		resp.RefreshToken = &raw
	}
	if user != nil {
		eventUserID = user.UserID
	}
	return resp, nil
}

// claimAuthorizationCode reserves the verified key before any signing work.
// A competing claim must prove the key observed under the same lock as the
// replay marker and revocation. Returning an error rolls back both effects.
func (h *Handlers) claimAuthorizationCode(ctx context.Context, res tenant.Resolved, clientID, hash string, at time.Time) (*store.AuthCode, error) {
	tid := res.Tenant.ID
	var ac *store.AuthCode
	var replay bool
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		// Policy writers and final mints lock the tenant before code/family rows.
		if _, err := tx.Tenants().Get(ctx, tid); err != nil {
			return err
		}
		var err error
		ac, err = tx.AuthCodes().Consume(ctx, tid, hash, at)
		replay = errors.Is(err, store.ErrAlreadyUsed)
		if err != nil && !replay {
			return err
		}
		if ac == nil || ac.ClientID != clientID || res.CheckOrigin(ac.Origin) != nil {
			return store.ErrNotFound
		}
		key := proofJKT(ctx)
		if ac.DPoPJKT != "" && ac.DPoPJKT != key {
			return &Error{Status: 400, Code: "invalid_dpop_proof", Description: "the proof could not be accepted"}
		}
		if replay {
			return tx.RefreshTokens().RevokeFamily(ctx, tid, familyForCode(hash), at)
		}
		if key != "" && ac.DPoPJKT == "" {
			return tx.AuthCodes().SetRedemptionBinding(ctx, tid, hash, "", key)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replay {
		return ac, store.ErrAlreadyUsed
	}
	return ac, nil
}
