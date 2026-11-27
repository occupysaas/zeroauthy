package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// familyForCIBA is the refresh token family started by a CIBA request.
func familyForCIBA(idHash string) string {
	return "rtf_" + secrets.HashToken("family:ciba:" + idHash)[:32]
}

func cibaError(code, desc string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: code, Description: desc}
}

// cibaGrant polls a backchannel authentication request (OpenID CIBA, poll
// mode; D-0100) with Auth0's answers.
func (h *Handlers) cibaGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (response *authapi.TokenResponse, failure *Error) {
	var eventConn *store.Connection
	var eventUserID string
	defer func() {
		if failure != nil && (failure.Code == "authorization_pending" || failure.Code == "slow_down") {
			return
		}
		code := "ciba_exchange_succeeded"
		if failure != nil {
			code = "ciba_exchange_failed"
		}
		h.event(ctx, res, c, code, eventConn, eventUserID)
	}()
	id := form.Get("auth_req_id")
	if id == "" {
		return nil, invalidRequest("auth_req_id is required")
	}
	ctx = logscrub.WithCredentials(ctx, id)
	tenantID := res.Tenant.ID
	repo, err := store.CIBA(ctx, h.Store)
	if err != nil {
		return nil, serverError()
	}
	hash := secrets.HashToken(id)
	// Another client's request is unknown to this client and does not move
	// (Review Focus 4).
	poll, rec, err := repo.PollCIBARequest(ctx, tenantID, hash, c.ClientID, h.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, cibaError("invalid_grant", "invalid auth_req_id")
	case err != nil:
		h.log().ErrorContext(ctx, "poll CIBA request", "tenant", tenantID, "err", err)
		return nil, serverError()
	case res.CheckOrigin(rec.Origin) != nil:
		return nil, cibaError("invalid_grant", "invalid auth_req_id")
	}
	switch poll {
	case store.CIBAPollPending:
		return nil, cibaError("authorization_pending", "The end-user authorization is pending")
	case store.CIBAPollSlowDown:
		e := cibaError("slow_down", fmt.Sprintf("You are polling faster than allowed. Try again in %d seconds.", rec.Interval))
		e.Interval = rec.Interval
		return nil, e
	case store.CIBAPollDenied, store.CIBAPollExpired:
		// Auth0 answers both with access_denied (LR41c-8).
		return nil, cibaError("access_denied", "The end-user denied the authorization request or it has been expired")
	case store.CIBAPollApproved:
		// Approved and now consumed: mint the tokens below.
	default:
		return nil, cibaError("invalid_grant", "invalid auth_req_id")
	}
	eventUserID = rec.UserID
	user, oerr := h.activeUser(ctx, tenantID, rec.UserID)
	if oerr != nil {
		return nil, oerr
	}
	eventConn = eventConnection(user, "")
	ctx = logs.WithEvent(ctx, logs.Event{UserID: user.UserID, UserName: user.Name, Connection: eventConn.Name, ConnectionID: eventConn.ID, Strategy: eventConn.Strategy})
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, rec.Audience)
	if oerr != nil {
		return nil, oerr
	}
	eff, oerr := h.openEffects(ctx, tenantID, actions.SealCIBA, hash, rec.ActionEffects)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(rec.GrantedScopes, rs, offlineAllowed(c, rs))
	resp, offline, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes, omitAtHash: true, effects: eff, authTime: rec.AuthTime, mfaAt: rec.MFAAt,
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
			expiresAt = h.now().UTC().Add(absolute)
		}
		rt, raw = h.newRefreshToken(ctx, c, tenantID, refreshGrant{
			origin:   res.Origin(),
			familyID: familyForCIBA(hash), userID: user.UserID, audience: rec.Audience, scopes: ceiling, expiresAt: expiresAt,
		})
	}
	err = h.mintTx(ctx, tenantID, user.UserID, &user.Version, func(tx store.Store) error {
		if rt == nil {
			return nil
		}
		return createInitialRefresh(ctx, tx, rt)
	})
	switch {
	case errors.Is(err, errUserChanged):
		return nil, cibaError("invalid_grant", "the user is not allowed to sign in")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt != nil {
		resp.RefreshToken = &raw
	}
	return resp, nil
}
