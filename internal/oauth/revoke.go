package oauth

import (
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
	if err := h.Store.RefreshTokens().RevokeFamily(ctx, tenantID, rt.FamilyID, h.now().UTC()); err != nil {
		h.log().ErrorContext(ctx, "revoke refresh tokens", "tenant", tenantID, "err", err)
		return serverError()
	}
	h.log().InfoContext(ctx, "refresh tokens revoked", "tenant", tenantID, "client_id", c.ClientID, "family", rt.FamilyID)
	return nil
}
