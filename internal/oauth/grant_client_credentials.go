// internal/oauth/grant_client_credentials.go
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
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
	if errors.Is(err, store.ErrNotFound) && !res.Tenant.Reserved && aud == tenant.ManagementAPIIdentifier(res.Tenant, h.BaseDomain) {
		// The tenant's Management API is created on first use. The system
		// tenant has none: only operators manage it.
		rs, err = tenantsetup.ManagementAPI(ctx, h.Store, res.Tenant, h.BaseDomain, h.now().UTC())
		if errors.Is(err, store.ErrConflict) {
			rs, err = h.Store.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
		}
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, accessDenied("unknown audience")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load resource server", "tenant", tenantID, "audience", aud, "err", err)
		return nil, serverError()
	}
	grant, err := h.Store.ClientGrants().Find(ctx, tenantID, c.ClientID, aud, store.SubjectTypeClient)
	if errors.Is(err, store.ErrNotFound) {
		grant, err = nil, nil
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client grant", "tenant", tenantID, "client_id", c.ClientID, "err", err)
		return nil, serverError()
	}
	if d := access.Decide(access.Input{Flow: access.ClientCredentials, Client: c, API: rs, ClientGrant: grant}); d.Err != nil {
		return nil, accessDenied(d.Err.Description)
	}
	if grant == nil {
		return nil, accessDenied("client is not authorized for this audience")
	}
	org, oerr := h.machineOrganization(ctx, res, form)
	if oerr != nil {
		return nil, oerr
	}
	orgID := ""
	if org != nil {
		orgID = org.ID
	}
	if err := orglogin.CheckMachineGrant(ctx, h.Store, tenantID, grant, orgID); err != nil {
		return nil, accessDenied("the organization grant is not eligible")
	}
	allowed := grant.EffectiveScopes(rs.Scopes)
	scopes, oerr := resolveScopes(form.Get("scope"), allowed, rs.Scopes)
	if oerr != nil {
		return nil, oerr
	}
	orgClaims := OrgClaims(res, org)
	scopes, claims, oerr := h.credentialsExchange(ctx, res, c, rs, strings.Fields(form.Get("scope")), scopes, allowed, org)
	if oerr != nil {
		return nil, oerr
	}

	lifetime := time.Duration(rs.TokenLifetime) * time.Second
	if lifetime <= 0 {
		lifetime = DefaultAccessTokenLifetime
	}
	// Trusted organization claims were frozen before Actions; final reads authorize issuance.
	if claims == nil {
		claims = map[string]any{}
	}
	for k, v := range orgClaims {
		claims[k] = v
	}
	// This transaction is issuance's authorization boundary. A revocation
	// committed before its policy reads wins; later writes do not cancel an
	// already approved issuance. Sign after commit because the key manager
	// uses the outer store (which memory/SQLite transactions exclusively hold).
	err = h.Store.WithTx(ctx, func(tx store.Store) error {
		currentClient, err := tx.Clients().Get(ctx, tenantID, c.ClientID)
		if err != nil {
			return err
		}
		currentAPI, err := tx.ResourceServers().GetByIdentifier(ctx, tenantID, aud)
		if err != nil {
			return err
		}
		currentGrant, err := tx.ClientGrants().Find(ctx, tenantID, c.ClientID, aud, store.SubjectTypeClient)
		if err != nil {
			return err
		}
		if currentGrant.ID != grant.ID {
			return orglogin.ErrNotMember
		}
		if d := access.Decide(access.Input{Flow: access.ClientCredentials, Client: currentClient, API: currentAPI, ClientGrant: currentGrant}); d.Err != nil {
			return orglogin.ErrNotMember
		}
		if err := orglogin.CheckMachineGrant(ctx, tx, tenantID, currentGrant, orgID); err != nil {
			return err
		}
		// Winning scope/API revocations also cap the already executed Action.
		currentAllowed := currentGrant.EffectiveScopes(currentAPI.Scopes)
		scopes = slices.DeleteFunc(scopes, func(scope string) bool { return !slices.Contains(currentAllowed, scope) })
		defined := []string{}
		for _, scope := range currentAPI.Scopes {
			defined = append(defined, scope.Value)
		}
		scopes = slices.DeleteFunc(scopes, func(scope string) bool { return !slices.Contains(defined, scope) })
		return nil
	})
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, orglogin.ErrNotMember) || errors.Is(err, store.ErrOrganizationsIIUnavailable) {
		return nil, accessDenied("the organization grant is no longer eligible")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "mint access token", "tenant", tenantID, "err", err)
		return nil, serverError()
	}
	token, err := h.Minter.AccessToken(ctx, AccessTokenParams{
		TenantID:     tenantID,
		Issuer:       res.Issuer(),
		Subject:      c.ClientID + "@clients",
		Audience:     []string{rs.Identifier},
		ClientID:     c.ClientID,
		Scopes:       scopes,
		GrantType:    "client-credentials",
		Lifetime:     lifetime,
		TokenDialect: rs.TokenDialect,
		CustomClaims: claims,
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

// credentialsExchange runs the tenant's credentials-exchange flow after
// client authentication and the client-grant check, before minting. It
// returns the scopes after the flow's target-scope edits, intersected with
// the client grant (allowed) and the API's defined scopes, and the filtered custom claims. A denial is
// the OAuth error its code names (invalid_scope and invalid_request 400,
// server_error 500, D-0053); a failed flow is server_error.
func (h *Handlers) credentialsExchange(ctx context.Context, res tenant.Resolved, c *store.Client, rs *store.ResourceServer, requested, scopes, allowed []string, org *store.Organization) ([]string, map[string]any, *Error) {
	if h.Actions == nil {
		return scopes, nil, nil
	}
	result, err := h.Actions.CredentialsExchange(ctx, actions.CredentialsInput{
		Tenant: res, Client: c, ResourceServer: rs, Request: requestInfoFrom(ctx),
		RequestedScopes: requested, TargetScopes: scopes, Organization: org,
	})
	if err != nil {
		var fe *actions.ErrFlow
		if !errors.As(err, &fe) {
			h.log().ErrorContext(ctx, "run credentials-exchange Actions", "tenant", res.Tenant.ID, "err", err)
		}
		return nil, nil, serverError()
	}
	if d := result.Denied; d != nil {
		status := http.StatusBadRequest
		if d.Code == "server_error" {
			status = http.StatusInternalServerError
		}
		return nil, nil, &Error{Status: status, Code: d.Code, Description: d.Reason}
	}
	// A grant's scopes outlive deleted API scopes; only defined ones count.
	defined := []string{}
	for _, v := range allowed {
		if slices.ContainsFunc(rs.Scopes, func(d store.Scope) bool { return d.Value == v }) {
			defined = append(defined, v)
		}
	}
	scopes = targetScopes(&result.Effects, scopes, defined)
	// Non-namespaced claims never reach the Management API.
	claims, err := actions.FilterClaims(actions.ClaimAccessToken, nil, result.Effects.AccessClaims, rs.IsSystem)
	if err != nil {
		h.log().ErrorContext(ctx, "apply Action custom claims", "tenant", res.Tenant.ID, "err", err)
		return nil, nil, serverError()
	}
	return scopes, claims, nil
}
