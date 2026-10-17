package oidc

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
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
	raw, ok, err := accessToken(w, r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_request"`)
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid_request", "an access token is required")
		return
	}
	var std jwt.Claims
	var extra struct {
		Scope string `json:"scope"`
	}
	if err := h.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra); err != nil {
		if errors.Is(err, keys.ErrInvalidToken) {
			invalidToken(w)
			return
		}
		h.internalError(w, r, res.Tenant.ID, "verify access token", err)
		return
	}
	// ValidateWithLeeway skips exp when it is absent, so require exp and
	// sub explicitly. Every error it returns is a claim-validation failure.
	if std.Expiry == nil || std.Subject == "" {
		invalidToken(w)
		return
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer:      res.Issuer(),
		AnyAudience: jwt.Audience{res.Issuer() + "userinfo"},
		Time:        h.now(),
	}, 0); err != nil {
		invalidToken(w)
		return
	}
	user, err := h.Store.Users().Get(ctx, res.Tenant.ID, std.Subject)
	if errors.Is(err, store.ErrNotFound) || (err == nil && user.Blocked) {
		invalidToken(w)
		return
	}
	if err != nil {
		h.internalError(w, r, res.Tenant.ID, "load user", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, claims.ForUser(user, strings.Fields(extra.Scope)))
}

func (h *Handlers) internalError(w http.ResponseWriter, r *http.Request, tenantID, what string, err error) {
	h.log().ErrorContext(r.Context(), "userinfo: "+what, "tenant", tenantID, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
}

func invalidToken(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo", error="invalid_token"`)
	httpx.WriteError(w, http.StatusUnauthorized, "invalid_token", "the access token is invalid or expired")
}

// maxUserinfoFormBytes bounds a form-encoded POST /userinfo body.
const maxUserinfoFormBytes = 64 << 10

// accessToken reads the access token from the Authorization header (RFC
// 6750 §2.1) or, on a form-encoded POST, from the access_token body
// parameter (§2.2). A request that uses both, repeats access_token or has
// an unreadable body is an invalid_request (§2, §3.1).
func accessToken(w http.ResponseWriter, r *http.Request) (string, bool, error) {
	header, hasHeader := bearerToken(r)
	if r.Method != http.MethodPost {
		return header, hasHeader, nil
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/x-www-form-urlencoded" {
		return header, hasHeader, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUserinfoFormBytes)
	if err := r.ParseForm(); err != nil {
		return "", false, errors.New("the request body could not be read")
	}
	body, inBody := r.PostForm["access_token"]
	switch {
	case !inBody:
		return header, hasHeader, nil
	case len(body) != 1:
		return "", false, errors.New("access_token must be sent once")
	case r.Header.Get("Authorization") != "":
		return "", false, errors.New("the access token must be sent in only one way")
	case strings.TrimSpace(body[0]) == "":
		return "", false, nil
	}
	return strings.TrimSpace(body[0]), true, nil
}

// bearerToken extracts an RFC 6750 §2.1 bearer token.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return "", false
	}
	return strings.TrimSpace(token), true
}
