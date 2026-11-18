package mgmt

import (
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"net/http"
)

// The contracts precede implementation; temporary handlers stay scoped.
func (h *Handlers) GetConnectionKeys(w http.ResponseWriter, r *http.Request, id string) {
	WriteError(w, 501, "not_implemented", "Connection keys are not implemented yet")
}
func (h *Handlers) PostConnectionKeys(w http.ResponseWriter, r *http.Request, id string) {
	WriteError(w, 501, "not_implemented", "Connection keys are not implemented yet")
}
func (h *Handlers) PostConnectionKeysRotate(w http.ResponseWriter, r *http.Request, id string) {
	WriteError(w, 501, "not_implemented", "Connection keys are not implemented yet")
}
func (h *Handlers) GetConnectionStatus(w http.ResponseWriter, r *http.Request, id string) {
	WriteError(w, 501, "not_implemented", "Connection status is not implemented yet")
}
func (h *Handlers) DeleteConnectionUsersByEmail(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.DeleteConnectionUsersByEmailParams) {
	WriteError(w, 501, "not_implemented", "Connection user deletion is not implemented yet")
}
