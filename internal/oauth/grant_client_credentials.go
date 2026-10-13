// internal/oauth/grant_client_credentials.go
package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// clientCredentials implements RFC 6749 §4.4. The client must be
// confidential and hold a client grant for the audience.
func (h *Handlers) clientCredentials(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	if c.TokenEndpointAuthMethod == store.AuthMethodNone {
		return nil, unauthorizedClient("client_credentials requires a confidential client")
	}
	tenantID := res.Tenant.ID
	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	if aud == "" {
		return nil, invalidRequest("audience is required because the tenant has no default audience")
	}

	rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
	if errors.Is(err, store.ErrNotFound) {
		return nil, accessDenied("unknown audience")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "audience", aud, "err", err)
		return nil, serverError()
	}
	grant, err := h.Store.ClientGrants().Find(ctx, tenantID, c.ClientID, aud)
	if errors.Is(err, store.ErrNotFound) {
		return nil, accessDenied("client is not authorized for this audience")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client grant", "tenant", tenantID, "client_id", c.ClientID, "err", err)
		return nil, serverError()
	}
	scopes, oerr := resolveScopes(form.Get("scope"), grant.Scopes, rs.Scopes)
	if oerr != nil {
		return nil, oerr
	}

	lifetime := time.Duration(rs.TokenLifetime) * time.Second
	if lifetime <= 0 {
		lifetime = DefaultAccessTokenLifetime
	}
	token, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID:  tenantID,
		Issuer:    res.Issuer(),
		Subject:   c.ClientID + "@clients",
		Audience:  []string{rs.Identifier},
		ClientID:  c.ClientID,
		Scopes:    scopes,
		GrantType: "client-credentials",
		Lifetime:  lifetime,
	})
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	resp := &authapi.TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(lifetime / time.Second),
	}
	if len(scopes) > 0 {
		s := strings.Join(scopes, " ")
		resp.Scope = &s
	}
	return resp, nil
}
