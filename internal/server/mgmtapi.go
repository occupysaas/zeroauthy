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

func (a mgmtAPI) GetUsers(w http.ResponseWriter, r *http.Request, p mgmtapi.GetUsersParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUsers(w, r, p) }, "read:users")
}

// CreateUser: create:users; app_metadata in the body also needs
// create:users_app_metadata or update:users_app_metadata, which the
// handler checks.
func (a mgmtAPI) CreateUser(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateUser, "create:users")
}

func (a mgmtAPI) GetUsersByEmail(w http.ResponseWriter, r *http.Request, p mgmtapi.GetUsersByEmailParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUsersByEmail(w, r, p) }, "read:users")
}

func (a mgmtAPI) GetUser(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetUserParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUser(w, r, id, p) }, "read:users")
}

// UpdateUser: update:users, or update:users_app_metadata for app_metadata;
// the handler checks which the body needs.
func (a mgmtAPI) UpdateUser(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateUser(w, r, id) }, "update:users", "update:users_app_metadata")
}

func (a mgmtAPI) DeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUser(w, r, id) }, "delete:users")
}

// LinkUserIdentity: update:users.
func (a mgmtAPI) LinkUserIdentity(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.LinkUserIdentity(w, r, id) }, "update:users")
}

// UnlinkUserIdentity: update:users.
func (a mgmtAPI) UnlinkUserIdentity(w http.ResponseWriter, r *http.Request, id, provider, userID string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UnlinkUserIdentity(w, r, id, provider, userID) }, "update:users")
}

// CreatePasswordChangeTicket: create:user_tickets.
func (a mgmtAPI) CreatePasswordChangeTicket(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreatePasswordChangeTicket, "create:user_tickets")
}

// CreateEmailVerificationTicket: create:user_tickets.
func (a mgmtAPI) CreateEmailVerificationTicket(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateEmailVerificationTicket, "create:user_tickets")
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

func (a mgmtAPI) TryConnectionScript(w http.ResponseWriter, r *http.Request, tenant, id, name string) {
	a.h.TryConnectionScript(w, r, tenant, id, name)
}

// GetUserSessions: read:sessions.
func (a mgmtAPI) GetUserSessions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserSessionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUserSessions(w, r, id) }, "read:sessions")
}

// DeleteUserSessions: delete:sessions.
func (a mgmtAPI) DeleteUserSessions(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUserSessions(w, r, id) }, "delete:sessions")
}

// GetUserRefreshTokens: read:refresh_tokens.
func (a mgmtAPI) GetUserRefreshTokens(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserRefreshTokensParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUserRefreshTokens(w, r, id) }, "read:refresh_tokens")
}

// DeleteUserRefreshTokens: delete:refresh_tokens.
func (a mgmtAPI) DeleteUserRefreshTokens(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUserRefreshTokens(w, r, id) }, "delete:refresh_tokens")
}

// GetSession: read:sessions.
func (a mgmtAPI) GetSession(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetSession(w, r, id) }, "read:sessions")
}

// DeleteSession: delete:sessions.
func (a mgmtAPI) DeleteSession(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteSession(w, r, id) }, "delete:sessions")
}

// GetRefreshToken: read:refresh_tokens.
func (a mgmtAPI) GetRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRefreshToken(w, r, id) }, "read:refresh_tokens")
}

// DeleteRefreshToken: delete:refresh_tokens.
func (a mgmtAPI) DeleteRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteRefreshToken(w, r, id) }, "delete:refresh_tokens")
}

// GetGrants: read:grants.
func (a mgmtAPI) GetGrants(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetGrantsParams) {
	scoped(w, r, a.h.GetGrants, "read:grants")
}

// DeleteGrantsByUser: delete:grants.
func (a mgmtAPI) DeleteGrantsByUser(w http.ResponseWriter, r *http.Request, _ mgmtapi.DeleteGrantsByUserParams) {
	scoped(w, r, a.h.DeleteGrantsByUser, "delete:grants")
}

// DeleteGrant: delete:grants.
func (a mgmtAPI) DeleteGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteGrant(w, r, id) }, "delete:grants")
}

// GetJob: create:users or read:users.
func (a mgmtAPI) GetJob(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetJob(w, r, id) }, "create:users", "read:users")
}

// GetJobErrors: create:users or read:users.
func (a mgmtAPI) GetJobErrors(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetJobErrors(w, r, id) }, "create:users", "read:users")
}

// CreateUsersImportJob: create:users.
func (a mgmtAPI) CreateUsersImportJob(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateUsersImportJob, "create:users")
}

// CreateUsersExportJob: read:users.
func (a mgmtAPI) CreateUsersExportJob(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateUsersExportJob, "read:users")
}

// CreateVerificationEmailJob: update:users.
func (a mgmtAPI) CreateVerificationEmailJob(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateVerificationEmailJob, "update:users")
}
