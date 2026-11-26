package mgmt

import (
	"context"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// MyOrgClientID is the caller the My Organization API's Management writes
// are logged as (Plan 42b Phase B, LR42b-24).
const MyOrgClientID = "my-organization-api"

var myOrgCaller = InProcessCaller{ClientID: MyOrgClientID, Scopes: []string{
	"read:connections", "create:connections", "update:connections", "delete:connections",
	"read:organization_connections", "create:organization_connections", "update:organization_connections", "delete:organization_connections",
	"read:scim_config", "create:scim_config", "update:scim_config", "delete:scim_config",
	"read:scim_token", "create:scim_token", "delete:scim_token",
}}

func (h *Handlers) myOrg(ctx context.Context, tn *store.Tenant, host, method, target string, body any, fn http.HandlerFunc) (AssistantResult, error) {
	return h.inProcess(ctx, tn, host, myOrgCaller, method, target, body, fn)
}

// MyOrgCreateConnection is POST /api/v2/connections.
func (h *Handlers) MyOrgCreateConnection(ctx context.Context, tn *store.Tenant, host string, body map[string]any) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodPost, "/connections", body, h.CreateConnection)
}

// MyOrgGetConnection is GET /api/v2/connections/{id}.
func (h *Handlers) MyOrgGetConnection(ctx context.Context, tn *store.Tenant, host, id string) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodGet, "/connections/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		h.GetConnection(w, r, id, mgmtapi.GetConnectionParams{})
	})
}

// MyOrgUpdateConnection is PATCH /api/v2/connections/{id}.
func (h *Handlers) MyOrgUpdateConnection(ctx context.Context, tn *store.Tenant, host, id string, body map[string]any) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodPatch, "/connections/"+id, body, func(w http.ResponseWriter, r *http.Request) { h.UpdateConnection(w, r, id) })
}

// MyOrgDeleteConnection is DELETE /api/v2/connections/{id}.
func (h *Handlers) MyOrgDeleteConnection(ctx context.Context, tn *store.Tenant, host, id string) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodDelete, "/connections/"+id, nil, func(w http.ResponseWriter, r *http.Request) { h.DeleteConnection(w, r, id) })
}

// MyOrgEnableOrganization is POST /api/v2/organizations/{id}/connections.
func (h *Handlers) MyOrgEnableOrganization(ctx context.Context, tn *store.Tenant, host, orgID string, body map[string]any) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodPost, "/organizations/"+orgID+"/connections", body, func(w http.ResponseWriter, r *http.Request) { h.CreateOrganizationAllConnection(w, r, orgID) })
}

// MyOrgUpdateOrganizationConnection is PATCH /api/v2/organizations/{id}/connections/{connection_id}.
func (h *Handlers) MyOrgUpdateOrganizationConnection(ctx context.Context, tn *store.Tenant, host, orgID, connID string, body map[string]any) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodPatch, "/organizations/"+orgID+"/connections/"+connID, body, func(w http.ResponseWriter, r *http.Request) { h.UpdateOrganizationAllConnection(w, r, orgID, connID) })
}

// MyOrgDisableOrganization is DELETE /api/v2/organizations/{id}/connections/{connection_id}.
func (h *Handlers) MyOrgDisableOrganization(ctx context.Context, tn *store.Tenant, host, orgID, connID string) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodDelete, "/organizations/"+orgID+"/connections/"+connID, nil, func(w http.ResponseWriter, r *http.Request) { h.DeleteOrganizationAllConnection(w, r, orgID, connID) })
}

// MyOrgCreateSCIM is POST /api/v2/connections/{id}/scim-configuration.
func (h *Handlers) MyOrgCreateSCIM(ctx context.Context, tn *store.Tenant, host, connID string) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodPost, "/connections/"+connID+"/scim-configuration", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { h.CreateScimConfiguration(w, r, connID) })
}

// MyOrgDeleteSCIM is DELETE /api/v2/connections/{id}/scim-configuration.
func (h *Handlers) MyOrgDeleteSCIM(ctx context.Context, tn *store.Tenant, host, connID string) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodDelete, "/connections/"+connID+"/scim-configuration", nil, func(w http.ResponseWriter, r *http.Request) { h.DeleteScimConfiguration(w, r, connID) })
}

// MyOrgCreateSCIMToken is POST /api/v2/connections/{id}/scim-configuration/tokens.
func (h *Handlers) MyOrgCreateSCIMToken(ctx context.Context, tn *store.Tenant, host, connID string, body map[string]any) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodPost, "/connections/"+connID+"/scim-configuration/tokens", body, func(w http.ResponseWriter, r *http.Request) { h.CreateScimToken(w, r, connID) })
}

// MyOrgDeleteSCIMToken is DELETE /api/v2/connections/{id}/scim-configuration/tokens/{token_id}.
func (h *Handlers) MyOrgDeleteSCIMToken(ctx context.Context, tn *store.Tenant, host, connID, tokenID string) (AssistantResult, error) {
	return h.myOrg(ctx, tn, host, http.MethodDelete, "/connections/"+connID+"/scim-configuration/tokens/"+tokenID, nil, func(w http.ResponseWriter, r *http.Request) { h.DeleteScimToken(w, r, connID, tokenID) })
}
