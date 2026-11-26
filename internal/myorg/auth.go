package myorg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/myorgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Caller is the organization administrator a request acts for.
type Caller struct {
	TenantID, UserID, ClientID, Host string
	Scopes                           []string
	Tenant                           *store.Tenant
	User                             *store.User
	Org                              *store.Organization
	// Config is the calling application's my_organization_configuration.
	Config *myorgrules.Config
	// API is the tenant's My Organization API.
	API *store.ResourceServer
}

// Has reports whether the token carries scope.
func (c *Caller) Has(scope string) bool { return slices.Contains(c.Scopes, scope) }

type claims struct {
	Confirmation map[string]any `json:"cnf"`
	Scope        string         `json:"scope"`
	AZP          string         `json:"azp"`
	ClientID     string         `json:"client_id"`
	GrantType    string         `json:"gty"`
	OrgID        string         `json:"org_id"`
	Operator     []string       `json:"https://zeroauthy.dev/operator"`
	Actor        map[string]any `json:"act"`
}

const leeway = 30 * time.Second

func (h *Handlers) api(ctx context.Context, t *store.Tenant) (*store.ResourceServer, error) {
	id := tenant.MyOrgIdentifier(t)
	if id == "" {
		return nil, store.ErrNotFound
	}
	rs, err := h.Store.ResourceServers().GetByIdentifier(ctx, t.ID, id)
	if err == nil && !rs.IsSystem {
		return nil, store.ErrNotFound
	}
	return rs, err
}

func orgNotFound() *Problem {
	return problem(http.StatusNotFound, "not_found", "Resource Not Found", "The organization does not exist.")
}

// authenticate checks the bearer token: signed by the tenant, issued on
// this host for this host's My Organization audience, unexpired, a user
// token with an org_id whose organization exists and still has the user as
// a member, from an application with a My Organization configuration.
func (h *Handlers) authenticate(r *http.Request) (*Caller, *Problem) {
	ctx := r.Context()
	res, ok := tenant.FromContext(ctx)
	if !ok || res.Tenant == nil || res.Tenant.Reserved {
		return nil, notFound("Not found.")
	}
	api, err := h.api(ctx, res.Tenant)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("The My Organization API is not active for this tenant.")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "my org: load the API", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	raw = strings.TrimSpace(raw)
	if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return nil, problem(http.StatusUnauthorized, "unauthorized", "Missing Token", "No auth token provided.")
	}
	var std jwt.Claims
	var extra claims
	if err := h.Keys.Verify(ctx, res.Tenant.ID, raw, &std, &extra); err != nil {
		if errors.Is(err, keys.ErrInvalidToken) {
			return nil, unauthorized("Invalid access token.")
		}
		h.log().ErrorContext(ctx, "my org: load keys", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	if std.Expiry == nil || std.Issuer != res.Issuer() {
		return nil, unauthorized("Invalid access token.")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{tenant.MyOrgAudience(res.Host)}, Time: h.now()}, leeway); err != nil {
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
	if extra.OrgID == "" {
		return nil, forbiddenDetail("The access token has no organization.")
	}
	u, err := h.Store.Users().Get(ctx, res.Tenant.ID, std.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return nil, unauthorized("Invalid access token.")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "my org: load the user", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	if u.Blocked {
		return nil, unauthorized("The user is blocked.")
	}
	org, err := h.Store.Organizations().Get(ctx, res.Tenant.ID, extra.OrgID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, orgNotFound()
	}
	if err != nil {
		h.log().ErrorContext(ctx, "my org: load the organization", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	member, err := h.Store.Organizations().IsMember(ctx, res.Tenant.ID, org.ID, u.UserID)
	if err != nil {
		h.log().ErrorContext(ctx, "my org: check membership", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	if !member {
		return nil, forbiddenDetail("The user is not a member of the organization.")
	}
	cfg, p := h.clientConfig(ctx, res.Tenant.ID, client)
	if p != nil {
		return nil, p
	}
	return &Caller{TenantID: res.Tenant.ID, UserID: u.UserID, ClientID: client, Host: res.Host, Scopes: strings.Fields(extra.Scope), Tenant: res.Tenant, User: u, Org: org, Config: cfg, API: api}, nil
}

// clientConfig loads the application's my_organization_configuration
// (LR42b-4): without one the API refuses its tokens.
func (h *Handlers) clientConfig(ctx context.Context, tid, clientID string) (*myorgrules.Config, *Problem) {
	repo, err := store.MyOrg(ctx, h.Store)
	if err != nil {
		h.log().ErrorContext(ctx, "my org: store", "err", err)
		return nil, serverError()
	}
	doc, err := repo.GetMyOrgClientConfig(ctx, tid, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, forbiddenDetail("The application has no My Organization configuration.")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "my org: load the configuration", "err", err)
		return nil, serverError()
	}
	cfg, err := myorgrules.Parse(json.RawMessage(doc.Doc))
	if err != nil {
		h.log().ErrorContext(ctx, "my org: stored configuration is invalid", "client_id", clientID, "err", err)
		return nil, serverError()
	}
	return cfg, nil
}
