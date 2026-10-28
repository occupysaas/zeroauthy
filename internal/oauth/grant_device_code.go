package oauth

import (
	"context"
	"errors"
	"net/url"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// familyForDevice is the refresh token family started by a device code.
func familyForDevice(deviceCodeHash string) string {
	return "rtf_" + secrets.HashToken("family:device:" + deviceCodeHash)[:32]
}

// deviceCodeGrant implements RFC 8628 §3.4-3.5: the device polls until the
// user decides.
func (h *Handlers) deviceCodeGrant(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	code := form.Get("device_code")
	if code == "" {
		return nil, invalidRequest("device_code is required")
	}
	tenantID := res.Tenant.ID
	hash := secrets.HashToken(code)
	// Check ownership before polling so another client cannot consume or
	// advance the code.
	d, err := h.Store.DeviceCodes().Get(ctx, tenantID, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, deviceInvalidGrant("invalid device code")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load device code", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if d.ClientID != c.ClientID || res.CheckOrigin(d.Origin) != nil {
		return nil, deviceInvalidGrant("invalid device code")
	}
	now := h.now()
	poll, err := h.Store.DeviceCodes().Poll(ctx, tenantID, hash, now)
	if err != nil {
		h.log().ErrorContext(ctx, "poll device code", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	switch poll.Outcome {
	case store.PollPending:
		return nil, authorizationPending()
	case store.PollSlowDown:
		return nil, slowDown()
	case store.PollDenied:
		return nil, accessDenied("the user denied the request")
	case store.PollExpired:
		return nil, expiredToken()
	case store.PollApproved:
		// Approved and now consumed: mint the tokens below.
	default:
		return nil, deviceInvalidGrant("invalid device code")
	}

	dc := poll.Code
	user, oerr := h.activeUser(ctx, tenantID, dc.UserID)
	if oerr != nil {
		return nil, deviceError(oerr)
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tenantID, dc.Audience)
	if oerr != nil {
		return nil, deviceError(oerr)
	}
	// The post-login flow ran at approval; its effects travel sealed.
	eff, oerr := h.openEffects(ctx, tenantID, actions.SealDevice, hash, dc.ActionEffects)
	if oerr != nil {
		return nil, oerr
	}
	scopes := userScopes(dc.GrantedScopes, rs, offlineAllowed(c, rs))
	// Device tokens belong to no browser session: no sid, no auth_time.
	resp, offline, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		user: user, rs: rs, lifetime: lifetime, scopes: scopes, omitAtHash: true, effects: eff,
	})
	if oerr != nil {
		return nil, oerr
	}
	var rt *store.RefreshToken
	var raw string
	if offline {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.UTC().Add(absolute)
		}
		rt, raw = h.newRefreshToken(c, tenantID, refreshGrant{
			origin:   res.Origin(),
			familyID: familyForDevice(hash), userID: user.UserID, audience: dc.Audience, scopes: scopes, expiresAt: expiresAt,
		})
	}
	// The user approved at /activate, possibly long ago, so there is no
	// Version to compare (D-0043); the user must still exist and not be
	// blocked when the tokens are minted.
	err = h.mintTx(ctx, tenantID, user.UserID, nil, func(tx store.Store) error {
		if rt == nil {
			return nil
		}
		return tx.RefreshTokens().Create(ctx, rt)
	})
	switch {
	case errors.Is(err, errUserChanged):
		return nil, deviceInvalidGrant("the user is not allowed to sign in")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	if rt != nil {
		resp.RefreshToken = &raw
	}
	return resp, nil
}

// deviceError gives a shared helper's invalid_grant the device flow's
// status, 403, like every other invalid_grant the device grant returns.
func deviceError(oerr *Error) *Error {
	if oerr.Code == "invalid_grant" {
		return deviceInvalidGrant(oerr.Description)
	}
	return oerr
}
