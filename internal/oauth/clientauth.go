// internal/oauth/clientauth.go
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const authFailed = "client authentication failed"

// authenticateClient implements token endpoint client authentication
// (RFC 6749 §2.3). The method used must be the one the client is
// registered with. Failures share one description so responses do not
// reveal which part was wrong; the reason is logged instead.
func (h *Handlers) authenticateClient(ctx context.Context, r *http.Request, form url.Values, tenantID string) (*store.Client, *Error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if !hasBasic && r.Header.Get("Authorization") != "" {
		// A present but unusable Authorization header must not fall through
		// to body credentials: that would silently pick one method.
		h.log().InfoContext(ctx, "client authentication failed: malformed Authorization header", "tenant", tenantID)
		return nil, invalidClient(authFailed, true)
	}
	if hasBasic {
		// RFC 6749 §2.3.1: credentials are form-urlencoded before base64.
		id, err1 := url.QueryUnescape(basicID)
		secret, err2 := url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return nil, invalidClient(authFailed, true)
		}
		basicID, basicSecret = id, secret
		if form.Get("client_secret") != "" {
			return nil, invalidRequest("use only one client authentication method")
		}
		if id := form.Get("client_id"); id != "" && id != basicID {
			return nil, invalidRequest("client_id does not match the HTTP Basic credentials")
		}
	}

	clientID, method, secret := form.Get("client_id"), store.AuthMethodNone, ""
	switch {
	case hasBasic:
		clientID, method, secret = basicID, store.AuthMethodClientSecretBasic, basicSecret
	case form.Get("client_secret") != "":
		method, secret = store.AuthMethodClientSecretPost, form.Get("client_secret")
	}
	if clientID == "" {
		return nil, invalidClient(authFailed, hasBasic)
	}

	c, err := h.Store.Clients().Get(ctx, tenantID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		h.log().InfoContext(ctx, "client authentication failed: unknown client", "tenant", tenantID, "client_id", clientID)
		return nil, invalidClient(authFailed, hasBasic)
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client", "tenant", tenantID, "client_id", clientID, "err", err)
		return nil, serverError()
	}
	if c.TokenEndpointAuthMethod != method {
		h.log().InfoContext(ctx, "client authentication failed: method mismatch",
			"tenant", tenantID, "client_id", clientID, "registered", c.TokenEndpointAuthMethod, "used", method)
		return nil, invalidClient(authFailed, hasBasic)
	}
	if method != store.AuthMethodNone && !h.secretValid(c, secret) {
		h.log().InfoContext(ctx, "client authentication failed: bad secret", "tenant", tenantID, "client_id", clientID)
		return nil, invalidClient(authFailed, hasBasic)
	}
	return c, nil
}

func (h *Handlers) secretValid(c *store.Client, secret string) bool {
	now := h.now()
	for _, s := range c.Secrets {
		if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
			continue
		}
		if ok, err := secrets.Verify(s.Hash, secret); err == nil && ok {
			return true
		}
	}
	return false
}
