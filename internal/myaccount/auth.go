package myaccount

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Caller is the user a My Account request acts for.
type Caller struct {
	TenantID, UserID, ClientID, Host string
	Scopes                           []string
	Tenant                           *store.Tenant
	User                             *store.User
}

// Has reports whether the token carries scope.
func (c *Caller) Has(scope string) bool { return slices.Contains(c.Scopes, scope) }

type claims struct {
	Confirmation map[string]any `json:"cnf"`
	Scope        string         `json:"scope"`
	AZP          string         `json:"azp"`
	ClientID     string         `json:"client_id"`
	GrantType    string         `json:"gty"`
	Operator     []string       `json:"https://zeroauthy.dev/operator"`
	Actor        map[string]any `json:"act"`
}

const leeway = 30 * time.Second

// active reports whether the tenant has activated the API (LR42a-4).
func (h *Handlers) active(ctx context.Context, t *store.Tenant) (bool, error) {
	id := tenant.MyAccountIdentifier(t)
	if id == "" {
		return false, nil
	}
	rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, t.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && rs.IsSystem, err
}

// authenticate checks the bearer token: signed by the tenant, issued on
// this host for this host's My Account audience, unexpired, a user token
// (never client credentials), not sender-constrained, for a user that
// still exists and is not blocked.
func (h *Handlers) authenticate(r *http.Request) (*Caller, *Problem) {
	res, ok := tenant.FromContext(r.Context())
	if !ok || res.Tenant == nil || res.Tenant.Reserved {
		return nil, notFound("Not found.")
	}
	if on, err := h.active(r.Context(), res.Tenant); err != nil {
		h.log().ErrorContext(r.Context(), "my account: load the API", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	} else if !on {
		return nil, notFound("The My Account API is not active for this tenant.")
	}
	scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	raw = strings.TrimSpace(raw)
	if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return nil, unauthorized("A Bearer access token is required.")
	}
	var std jwt.Claims
	var extra claims
	if err := h.Keys.Verify(r.Context(), res.Tenant.ID, raw, &std, &extra); err != nil {
		if errors.Is(err, keys.ErrInvalidToken) {
			return nil, unauthorized("Invalid access token.")
		}
		h.log().ErrorContext(r.Context(), "my account: load keys", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	if std.Expiry == nil || std.Issuer != res.Issuer() {
		return nil, unauthorized("Invalid access token.")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{tenant.MyAccountAudience(res.Host)}, Time: h.now()}, leeway); err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return nil, unauthorized("The access token has expired.")
		}
		return nil, unauthorized("Invalid access token.")
	}
	client := extra.AZP
	if client == "" {
		client = extra.ClientID
	}
	if len(extra.Confirmation) > 0 || len(extra.Operator) > 0 || extra.Actor != nil || client == "" ||
		extra.GrantType == "client-credentials" || std.Subject == "" || strings.HasSuffix(std.Subject, "@clients") {
		return nil, unauthorized("Only user access tokens are accepted.")
	}
	u, err := h.Store.Users().Get(r.Context(), res.Tenant.ID, std.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return nil, unauthorized("Invalid access token.")
	}
	if err != nil {
		h.log().ErrorContext(r.Context(), "my account: load the user", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	if u.Blocked {
		return nil, unauthorized("The user is blocked.")
	}
	return &Caller{TenantID: res.Tenant.ID, UserID: u.UserID, ClientID: client, Host: res.Host, Scopes: strings.Fields(extra.Scope), Tenant: res.Tenant, User: u}, nil
}
