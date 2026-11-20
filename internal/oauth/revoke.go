package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// OauthRevoke implements POST /oauth/revoke (RFC 7009). Only refresh
// tokens are stored, so only they can be revoked; revoking one revokes its
// whole family (D-0013).
func (h *Handlers) OauthRevoke(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	if oerr := h.revoke(w, r, res); oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) revoke(w http.ResponseWriter, r *http.Request, res tenant.Resolved) *Error {
	ctx := r.Context()
	tenantID := res.Tenant.ID
	form, oerr := parseTokenRequest(w, r)
	if oerr != nil {
		return oerr
	}
	ctx = r.Context()
	c, oerr := h.authenticateClient(ctx, r, form, tenantID)
	if oerr != nil {
		return oerr
	}
	token := form.Get("token")
	if token == "" {
		return invalidRequest("token is required")
	}
	rt, err := h.Store.RefreshTokens().GetByTokenHash(ctx, tenantID, secrets.HashToken(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil // RFC 7009 §2.2: unknown tokens are not an error
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load refresh token", "tenant", tenantID, "err", err)
		return serverError()
	}
	if res.CheckOrigin(rt.Origin) != nil {
		return nil // another origin's token is unknown here (RFC 7009 §2.2)
	}
	if rt.ClientID != c.ClientID {
		return invalidGrant("the token was not issued to this client")
	}
	if e := h.verifyProofHeader(w, r, res, c.TokenEndpointAuthMethod == store.AuthMethodNone, rt.DPoPJKT, false); e != nil {
		return e
	}
	ctx = r.Context()
	if rt.Access == "online" {
		if e := h.endOnlineSession(ctx, res, rt); e != nil {
			return serverError()
		}
		return nil
	}
	revoked := rt.RevokedAt == nil
	err = store.CheckRefreshTokensIISupport(ctx, h.Store)
	switch {
	case err == nil:
		revoked, err = h.revokeOffline(ctx, res, rt)
	case errors.Is(err, store.ErrRefreshTokensIIUnavailable) && !errors.Is(err, store.ErrRefreshTokensIISupportLost):
		err = h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, rt.FamilyID, h.now().UTC())
	}
	if err != nil {
		h.log().ErrorContext(ctx, "revoke refresh tokens", "tenant", tenantID, "err", err)
		return serverError()
	}
	if revoked {
		h.event(requestEventContext(r), res, c, "srrt", nil, rt.UserID)
		h.log().InfoContext(ctx, "refresh tokens revoked", "tenant", tenantID, "client_id", c.ClientID, "family", rt.FamilyID)
	}
	return nil
}

// revokeOffline chooses the revocation scope under the tenant policy lock.
func (h *Handlers) revokeOffline(ctx context.Context, res tenant.Resolved, rt *store.RefreshToken) (bool, error) {
	tid := res.Tenant.ID
	var revoked bool
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		if err := store.CheckRefreshTokensIISupport(ctx, tx); err != nil {
			return err
		}
		t, err := tx.Tenants().Get(ctx, tid)
		if err != nil {
			return err
		}
		flags, _ := t.SettingsExtra["flags"].(map[string]any)
		deleteGrant, _ := flags["revoke_refresh_token_grant"].(bool)
		if deleteGrant {
			if _, err := tx.Users().GetForUpdate(ctx, tid, rt.UserID); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return nil
				}
				return err
			}
		}
		current, err := tx.RefreshTokens().GetByTokenHash(ctx, tid, rt.TokenHash)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		at := h.now().UTC()
		if current.ID != rt.ID || current.UserID != rt.UserID || current.ClientID != rt.ClientID ||
			current.DPoPJKT != rt.DPoPJKT || res.CheckOrigin(current.Origin) != nil {
			return nil
		}
		if !deleteGrant || current.RevokedAt != nil || refreshExpired(current, at) {
			// A stale presentation can still have a live family successor.
			revoked = current.RevokedAt == nil
			return tx.RefreshTokens().RevokeFamily(ctx, tid, current.FamilyID, at)
		}
		if current.RotatedAt != nil {
			c, err := tx.Clients().Get(ctx, tid, current.ClientID)
			if err != nil {
				return err
			}
			err = checkRefreshRotation(ctx, tx.RefreshTokens(), current, c.RefreshToken, at, true)
			switch {
			case errors.Is(err, store.ErrAlreadyUsed):
				// CheckRotation revoked the spent token's own family. Commit
				// that result without consulting or deleting any grant.
				revoked = true
				return nil
			case errors.Is(err, store.ErrNotFound):
				return nil
			case err != nil:
				return err
			}
		}
		audience := current.Audience
		if audience == "" {
			audience = res.Issuer() + "userinfo"
		}
		g, err := tx.UserGrants().Find(ctx, tid, current.ClientID, current.UserID, audience)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil {
			if err := tx.UserGrants().Delete(ctx, tid, g.ID); err != nil {
				return err
			}
		}
		// First-party clients can have live tokens without a consent row.
		if _, err := tx.RefreshTokens().RevokeByUserClient(ctx, tid, current.UserID, current.ClientID, audience, at); err != nil {
			return err
		}
		revoked = true
		_, err = tx.Users().BumpVersion(ctx, tid, current.UserID)
		return err
	})
	return revoked && err == nil, err
}
