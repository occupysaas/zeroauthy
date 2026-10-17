// Package oidc serves OpenID Connect metadata (discovery, JWKS), /userinfo and the logout endpoints.
package oidc

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Metadata is cacheable briefly: keys are pre-published as "next" before
// they sign anything, so a short cache never hides a signing key.
const metadataCacheControl = "public, max-age=300"

type Handlers struct {
	Keys     *keys.Manager
	Store    store.Store
	Sessions *session.Manager
	Log      *slog.Logger
	Now      func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Configuration is OpenID Provider metadata (OpenID Connect Discovery 1.0
// §3). It lists only what this server implements.
type Configuration struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	// RequestURIParameterSupported is always false (D-0030): request_uri is
	// accepted only from /oauth/par. OIDC Discovery defaults it to true.
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

func (h *Handlers) Discovery(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	base := strings.TrimSuffix(res.Issuer(), "/")
	w.Header().Set("Cache-Control", metadataCacheControl)
	cfg := Configuration{
		Issuer:                            res.Issuer(),
		AuthorizationEndpoint:             base + "/authorize",
		TokenEndpoint:                     base + "/oauth/token",
		RevocationEndpoint:                base + "/oauth/revoke",
		DeviceAuthorizationEndpoint:       base + "/oauth/device/code",
		UserinfoEndpoint:                  base + "/userinfo",
		JWKSURI:                           base + "/.well-known/jwks.json",
		EndSessionEndpoint:                base + "/oidc/logout",
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query", "fragment", "form_post", "web_message"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token", "password", "http://auth0.com/oauth/grant-type/password-realm", "urn:ietf:params:oauth:grant-type:device_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access"},
		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "at_hash",
			"name", "nickname", "picture", "updated_at", "email", "email_verified"},
	}
	if res.Tenant.PushedAuthorizationRequestsSupported {
		cfg.PushedAuthorizationRequestEndpoint = base + "/oauth/par" // P8
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handlers) Jwks(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	set, err := h.Keys.JWKS(r.Context(), res.Tenant.ID)
	if err != nil {
		h.log().ErrorContext(r.Context(), "load JWKS", "tenant", res.Tenant.ID, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	w.Header().Set("Cache-Control", metadataCacheControl)
	httpx.WriteJSON(w, http.StatusOK, set)
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}
