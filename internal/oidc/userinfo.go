package oidc

import (
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Userinfo implements GET and POST /userinfo (OpenID Connect Core §5.3).
func (h *Handlers) Userinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Cache-Control", "no-store")
	res, ok := tenant.FromContext(ctx)
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	raw, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_request", "an access token is required")
		return
	}
	var std jwt.Claims
	var extra struct {
		Scope string `json:"scope"`
	}
	err := h.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra)
	if err == nil {
		err = std.ValidateWithLeeway(jwt.Expected{
			Issuer:      res.Issuer(),
			AnyAudience: jwt.Audience{res.Issuer() + "userinfo"},
			Time:        h.now(),
		}, 0)
	}
	if err != nil {
		invalidToken(w)
		return
	}
	user, err := h.Store.Users().Get(ctx, res.Tenant.ID, std.Subject)
	if err != nil || user.Blocked {
		invalidToken(w)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, claims.ForUser(user, strings.Fields(extra.Scope)))
}

func invalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
	httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "the access token is invalid or expired")
}

// bearerToken extracts an RFC 6750 §2.1 bearer token.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}
