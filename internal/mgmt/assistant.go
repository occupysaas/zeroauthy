package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// The self-service assistant (Plan 37c Phase B) writes through the
// Management API's own handlers, so a connection it creates passes exactly
// the rules a Management request does (validation, guarded metadata
// fetches, secret sealing, logs). It acts as the caller AssistantClientID
// with only these scopes; the assistant decides what it may ask for.

// AssistantClientID is the caller recorded for assistant writes.
const AssistantClientID = "self-service-assistant"

var assistantScopes = []string{"read:connections", "create:connections", "update:connections", "create:organization_connections", "create:scim_config", "create:scim_token"}

// AssistantResult is a Management response: status and JSON body.
type AssistantResult struct {
	Status int
	Body   json.RawMessage
}

// OK reports a 2xx status.
func (r AssistantResult) OK() bool { return r.Status >= 200 && r.Status < 300 }

// Message is the Management error message of a failed request.
func (r AssistantResult) Message() string {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(r.Body, &e)
	return e.Message
}

// InProcessCaller is the Management API caller of an in-process call: a
// zeroauthy surface acting as a machine client with fixed scopes.
type InProcessCaller struct {
	ClientID string
	Scopes   []string
}

var assistantCaller = InProcessCaller{ClientID: AssistantClientID, Scopes: assistantScopes}

func (h *Handlers) assistantCall(ctx context.Context, tn *store.Tenant, host, method, target string, body any, fn http.HandlerFunc) (AssistantResult, error) {
	return h.inProcess(ctx, tn, host, assistantCaller, method, target, body, fn)
}

// inProcess runs fn as the Management API request method target with body,
// for caller c, through the log middleware, and returns its response.
func (h *Handlers) inProcess(ctx context.Context, tn *store.Tenant, host string, c InProcessCaller, method, target string, body any, fn http.HandlerFunc) (AssistantResult, error) {
	var rd *bytes.Reader
	if body == nil {
		rd = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return AssistantResult{}, err
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequestWithContext(ctx, method, "https://"+host+"/api/v2"+target, rd)
	req.Header.Set("Content-Type", "application/json")
	rctx := tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: tn, Host: host})
	req = req.WithContext(WithCaller(rctx, Caller{Kind: M2M, ClientID: c.ClientID, Scopes: c.Scopes}))
	rec := httptest.NewRecorder()
	h.LogMiddleware(fn).ServeHTTP(rec, req)
	return AssistantResult{Status: rec.Code, Body: rec.Body.Bytes()}, nil
}

// AssistantCreateConnection is POST /api/v2/connections.
func (h *Handlers) AssistantCreateConnection(ctx context.Context, tn *store.Tenant, host string, body map[string]any) (AssistantResult, error) {
	return h.assistantCall(ctx, tn, host, http.MethodPost, "/connections", body, h.CreateConnection)
}

// AssistantGetConnection is GET /api/v2/connections/{id}: the connection
// as the Management API shows it (no secrets, no internal options).
func (h *Handlers) AssistantGetConnection(ctx context.Context, tn *store.Tenant, host, id string) (AssistantResult, error) {
	return h.assistantCall(ctx, tn, host, http.MethodGet, "/connections/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		h.GetConnection(w, r, id, mgmtapi.GetConnectionParams{})
	})
}

// AssistantUpdateConnection is PATCH /api/v2/connections/{id}.
func (h *Handlers) AssistantUpdateConnection(ctx context.Context, tn *store.Tenant, host, id string, body map[string]any) (AssistantResult, error) {
	return h.assistantCall(ctx, tn, host, http.MethodPatch, "/connections/"+id, body, func(w http.ResponseWriter, r *http.Request) { h.UpdateConnection(w, r, id) })
}

// AssistantEnableOrganization is POST /api/v2/organizations/{id}/connections.
func (h *Handlers) AssistantEnableOrganization(ctx context.Context, tn *store.Tenant, host, orgID string, body map[string]any) (AssistantResult, error) {
	return h.assistantCall(ctx, tn, host, http.MethodPost, "/organizations/"+orgID+"/connections", body, func(w http.ResponseWriter, r *http.Request) { h.CreateOrganizationConnection(w, r, orgID) })
}

// AssistantCreateSCIM creates the connection's SCIM configuration (when it
// has none) and one token, returned once.
func (h *Handlers) AssistantCreateSCIM(ctx context.Context, tn *store.Tenant, host, connID string, token map[string]any) (AssistantResult, error) {
	res, err := h.assistantCall(ctx, tn, host, http.MethodPost, "/connections/"+connID+"/scim-configuration", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { h.CreateScimConfiguration(w, r, connID) })
	if err != nil || !res.OK() && res.Status != http.StatusBadRequest {
		return res, err
	}
	if res.Status == http.StatusBadRequest && res.Message() != errSCIMConfigExists.Message {
		return res, nil
	}
	return h.assistantCall(ctx, tn, host, http.MethodPost, "/connections/"+connID+"/scim-configuration/tokens", token, func(w http.ResponseWriter, r *http.Request) { h.CreateScimToken(w, r, connID) })
}
