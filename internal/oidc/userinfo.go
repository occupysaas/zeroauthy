package oidc

import (
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"mime"
	"net/http"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/dpop"
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
	scheme, headerToken, headerOK := strings.Cut(r.Header.Get("Authorization"), " ")
	proofScheme := headerOK && strings.EqualFold(scheme, "DPoP")
	raw, ok, err := accessToken(w, r)
	if proofScheme {
		if len(r.Header.Values("Authorization")) != 1 || strings.TrimSpace(headerToken) == "" || r.PostForm.Has("access_token") {
			invalidToken(w)
			return
		}
		raw, ok = strings.TrimSpace(headerToken), true
	}
	if errors.Is(err, errBodyTooLarge) {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "the request body exceeds 64 KB")
		return
	}
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
	// Type is a protected JOSE header: inspect it, then authenticate the entire
	// token below before using claims. Reject unrelated JWT formats explicitly.
	parsed, parseErr := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.PS256})
	if parseErr != nil || len(parsed.Headers) != 1 {
		invalidToken(w)
		return
	}
	tokenType, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if tokenType != "JWT" && tokenType != "at+jwt" {
		invalidToken(w)
		return
	}
	var std jwt.Claims
	var extra struct {
		Confirmation *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		SessionClaims struct {
			AuthTime int64  `json:"auth_time"`
			ACR      string `json:"acr"`
		} `json:"https://zeroauthy.dev/userinfo"`
		SessionID       string `json:"sid"`
		Scope           string `json:"scope"`
		OrgID           string `json:"org_id"`
		OrgName         string `json:"org_name"`
		ClientID        string `json:"client_id"`
		AuthorizedParty string `json:"azp"`
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
	if std.Expiry == nil || std.Subject == "" || !slices.Contains(strings.Fields(extra.Scope), "openid") ||
		(tokenType == "at+jwt" && (extra.ClientID == "" || std.IssuedAt == nil || std.ID == "")) {
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
	if extra.Confirmation != nil || proofScheme {
		if extra.Confirmation == nil || extra.Confirmation.JKT == "" || !proofScheme || h.DPoP == nil {
			invalidToken(w)
			return
		}
		proof, failure := h.DPoP.Verify(ctx, r, res, dpop.UserInfo, true, raw, extra.Confirmation.JKT)
		if failure != nil {
			if failure.Internal {
				httpx.WriteError(w, 500, "server_error", "proof verification unavailable")
				return
			}
			w.Header().Set("WWW-Authenticate", `DPoP error="`+failure.Code+`"`)
			if failure.Nonce != "" {
				w.Header().Set("DPoP-Nonce", failure.Nonce)
			}
			httpx.WriteError(w, 401, failure.Code, "proof could not be accepted")
			return
		}
		if proof.Nonce != "" {
			w.Header().Set("DPoP-Nonce", proof.Nonce)
		}
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
	scopes := strings.Fields(extra.Scope)
	if extra.ClientID == "" {
		extra.ClientID = extra.AuthorizedParty
	}
	if extra.ClientID != "" {
		client, err := h.Store.Clients().Get(ctx, res.Tenant.ID, extra.ClientID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.internalError(w, r, res.Tenant.ID, "load client", err)
			return
		}
		if client != nil {
			if !access.OIDCScopeAllowed(client, "openid") {
				invalidToken(w)
				return
			}
			scopes = slices.DeleteFunc(scopes, func(scope string) bool { return !access.OIDCScopeAllowed(client, scope) })
		}
	}
	body := claims.ForUser(user, scopes)
	if extra.SessionClaims.AuthTime > 0 {
		body["auth_time"] = extra.SessionClaims.AuthTime
	}
	if extra.SessionClaims.ACR == claims.ACRMultiFactor {
		body["acr"] = extra.SessionClaims.ACR
	}
	if extra.OrgID != "" {
		body["org_id"] = extra.OrgID
	}
	if extra.OrgName != "" {
		body["org_name"] = extra.OrgName
	}
	if extra.SessionID != "" && extra.ClientID != "" {
		session, e := h.Store.Sessions().Get(ctx, res.Tenant.ID, extra.SessionID)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			h.internalError(w, r, res.Tenant.ID, "load session claims", e)
			return
		}
		if e == nil && session.UserID == user.UserID {
			raw := session.UserinfoClaims[extra.ClientID]
			if raw != "" {
				var custom map[string]any
				if store.ValidateSessionClaims(raw) != nil || json.Unmarshal([]byte(raw), &custom) != nil {
					h.internalError(w, r, res.Tenant.ID, "decode session claims", store.ErrInvalid)
					return
				}
				filtered, e := actions.FilterClaims(actions.ClaimIDToken, body, custom, false)
				if e != nil {
					h.internalError(w, r, res.Tenant.ID, "filter session claims", e)
					return
				}
				for k, v := range filtered {
					body[k] = v
				}
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, body)
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

var errBodyTooLarge = errors.New("the request body is too large")

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
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return "", false, errBodyTooLarge
		}
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
