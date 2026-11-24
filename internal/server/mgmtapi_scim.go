package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// SCIM configuration and token routes (Plan 37c).

func (a mgmtAPI) ListScimConfigurations(w http.ResponseWriter, r *http.Request, _ mgmtapi.ListScimConfigurationsParams) {
	scoped(w, r, a.h.ListScimConfigurations, "read:scim_config")
}
func (a mgmtAPI) GetScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetScimConfiguration(w, r, id) }, "read:scim_config")
}
func (a mgmtAPI) CreateScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateScimConfiguration(w, r, id) }, "create:scim_config")
}
func (a mgmtAPI) UpdateScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateScimConfiguration(w, r, id) }, "update:scim_config")
}
func (a mgmtAPI) DeleteScimConfiguration(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteScimConfiguration(w, r, id) }, "delete:scim_config")
}
func (a mgmtAPI) GetScimDefaultMapping(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetScimDefaultMapping(w, r, id) }, "read:scim_config")
}
func (a mgmtAPI) ListScimTokens(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListScimTokens(w, r, id) }, "read:scim_token")
}
func (a mgmtAPI) CreateScimToken(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateScimToken(w, r, id) }, "create:scim_token")
}
func (a mgmtAPI) DeleteScimToken(w http.ResponseWriter, r *http.Request, id, tokenID string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteScimToken(w, r, id, tokenID) }, "delete:scim_token")
}
