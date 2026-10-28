// internal/oauth/token.go
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type grantHandler func(h *Handlers, ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error)

// grantHandlers maps grant_type to its implementation.
var grantHandlers = map[string]grantHandler{
	"authorization_code": (*Handlers).authorizationCode,
	"client_credentials": (*Handlers).clientCredentials,
	"refresh_token":      (*Handlers).refreshToken,
	"password":           (*Handlers).passwordGrant,
	GrantPasswordRealm:   (*Handlers).passwordRealmGrant,
	GrantDeviceCode:      (*Handlers).deviceCodeGrant,
}

// OauthToken implements POST /oauth/token.
func (h *Handlers) OauthToken(w http.ResponseWriter, r *http.Request) {
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		writeError(w, serverError())
		return
	}
	resp, oerr := h.token(w, r, res)
	if oerr != nil {
		writeError(w, oerr)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handlers) token(w http.ResponseWriter, r *http.Request, res tenant.Resolved) (*authapi.TokenResponse, *Error) {
	form, oerr := parseTokenRequest(w, r)
	if oerr != nil {
		return nil, oerr
	}
	grantType := form.Get("grant_type")
	if grantType == "" {
		return nil, invalidRequest("grant_type is required")
	}
	grant, ok := grantHandlers[grantType]
	if !ok {
		return nil, unsupportedGrantType(fmt.Sprintf("grant type %q is not supported", grantType))
	}
	client, oerr := h.authenticateClient(r.Context(), r, form, res.Tenant.ID)
	if oerr != nil {
		return nil, oerr
	}
	if !slices.Contains(client.GrantTypes, grantType) {
		return nil, unauthorizedClient(fmt.Sprintf("grant type %q is not allowed for this client", grantType))
	}
	// Grants that throttle by end user see the IP through the context.
	ip := h.endUserIP(r, client)
	ctx := withClientIP(r.Context(), ip)
	ctx = withRequestInfo(ctx, r, ip, form)
	return grant(h, ctx, res, client, form)
}
