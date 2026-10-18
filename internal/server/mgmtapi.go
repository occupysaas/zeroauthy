package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

// mgmtAPI adapts mgmt.Handlers to the generated ServerInterface, adding
// each operation's scope check. The var _ assertion fails to compile when
// api/management.yaml gains an operation that has no method here.
type mgmtAPI struct{ h *mgmt.Handlers }

var _ mgmtapi.ServerInterface = mgmtAPI{}

// scoped runs fn for a caller holding any of scopes.
func scoped(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc, scopes ...string) {
	mgmt.Require(scopes...)(fn).ServeHTTP(w, r)
}

func (a mgmtAPI) GetClients(w http.ResponseWriter, r *http.Request, p mgmtapi.GetClientsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClients(w, r, p) }, "read:clients")
}

func (a mgmtAPI) CreateClient(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateClient, "create:clients")
}

func (a mgmtAPI) GetClient(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetClientParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClient(w, r, id, p) }, "read:clients")
}

// UpdateClient: update:clients, or update:client_keys for the secret; the
// handler checks which the body needs.
func (a mgmtAPI) UpdateClient(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateClient(w, r, id) }, "update:clients", "update:client_keys")
}

func (a mgmtAPI) DeleteClient(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteClient(w, r, id) }, "delete:clients")
}

func (a mgmtAPI) RotateClientSecret(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RotateClientSecret(w, r, id) }, "update:client_keys")
}

func (a mgmtAPI) GetResourceServers(w http.ResponseWriter, r *http.Request, p mgmtapi.GetResourceServersParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetResourceServers(w, r, p) }, "read:resource_servers")
}

func (a mgmtAPI) CreateResourceServer(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateResourceServer, "create:resource_servers")
}

func (a mgmtAPI) GetResourceServer(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetResourceServerParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetResourceServer(w, r, id, p) }, "read:resource_servers")
}

func (a mgmtAPI) UpdateResourceServer(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateResourceServer(w, r, id) }, "update:resource_servers")
}

func (a mgmtAPI) DeleteResourceServer(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteResourceServer(w, r, id) }, "delete:resource_servers")
}

func (a mgmtAPI) GetClientGrants(w http.ResponseWriter, r *http.Request, p mgmtapi.GetClientGrantsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClientGrants(w, r, p) }, "read:client_grants")
}

func (a mgmtAPI) CreateClientGrant(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateClientGrant, "create:client_grants")
}

func (a mgmtAPI) GetClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClientGrant(w, r, id) }, "read:client_grants")
}

func (a mgmtAPI) UpdateClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateClientGrant(w, r, id) }, "update:client_grants")
}

func (a mgmtAPI) DeleteClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteClientGrant(w, r, id) }, "delete:client_grants")
}

func (a mgmtAPI) GetConnections(w http.ResponseWriter, r *http.Request, p mgmtapi.GetConnectionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnections(w, r, p) }, "read:connections")
}

func (a mgmtAPI) CreateConnection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateConnection, "create:connections")
}

func (a mgmtAPI) GetConnection(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetConnectionParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnection(w, r, id, p) }, "read:connections")
}

func (a mgmtAPI) UpdateConnection(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateConnection(w, r, id) }, "update:connections")
}

func (a mgmtAPI) DeleteConnection(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteConnection(w, r, id) }, "delete:connections")
}

func (a mgmtAPI) GetConnectionClients(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetConnectionClientsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnectionClients(w, r, id, p) }, "read:connections")
}

func (a mgmtAPI) UpdateConnectionClients(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateConnectionClients(w, r, id) }, "update:connections")
}

// The system API: the router lets only operators reach it (operatorOnly).

func (a mgmtAPI) GetTenants(w http.ResponseWriter, r *http.Request)   { a.h.GetTenants(w, r) }
func (a mgmtAPI) CreateTenant(w http.ResponseWriter, r *http.Request) { a.h.CreateTenant(w, r) }

func (a mgmtAPI) UpdateTenant(w http.ResponseWriter, r *http.Request, name string) {
	a.h.UpdateTenant(w, r, name)
}

func (a mgmtAPI) DeleteTenant(w http.ResponseWriter, r *http.Request, name string, p mgmtapi.DeleteTenantParams) {
	a.h.DeleteTenant(w, r, name, p)
}

func (a mgmtAPI) GetOperators(w http.ResponseWriter, r *http.Request)   { a.h.GetOperators(w, r) }
func (a mgmtAPI) CreateOperator(w http.ResponseWriter, r *http.Request) { a.h.CreateOperator(w, r) }

func (a mgmtAPI) DeleteOperator(w http.ResponseWriter, r *http.Request, id string) {
	a.h.DeleteOperator(w, r, id)
}
