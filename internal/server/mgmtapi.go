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
