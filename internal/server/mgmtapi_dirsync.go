package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// Directory provisioning routes (Plan 37c Phase C).

func (a mgmtAPI) ListDirectoryProvisionings(w http.ResponseWriter, r *http.Request, _ mgmtapi.ListDirectoryProvisioningsParams) {
	scoped(w, r, a.h.ListDirectoryProvisionings, "read:directory_provisionings")
}
func (a mgmtAPI) GetDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetDirectoryProvisioning(w, r, id) }, "read:directory_provisionings")
}
func (a mgmtAPI) CreateDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateDirectoryProvisioning(w, r, id) }, "create:directory_provisionings")
}
func (a mgmtAPI) UpdateDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateDirectoryProvisioning(w, r, id) }, "update:directory_provisionings")
}
func (a mgmtAPI) DeleteDirectoryProvisioning(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteDirectoryProvisioning(w, r, id) }, "delete:directory_provisionings")
}
func (a mgmtAPI) GetDirectoryProvisioningDefaultMapping(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetDirectoryProvisioningDefaultMapping(w, r, id) }, "read:directory_provisionings")
}
func (a mgmtAPI) CreateDirectorySynchronization(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateDirectorySynchronization(w, r, id) }, "create:directory_provisionings")
}
func (a mgmtAPI) ListSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListSynchronizedGroupsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListSynchronizedGroups(w, r, id) }, "read:directory_provisionings")
}
func (a mgmtAPI) AddSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AddSynchronizedGroups(w, r, id) }, "update:directory_provisionings")
}
func (a mgmtAPI) ReplaceSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ReplaceSynchronizedGroups(w, r, id) }, "update:directory_provisionings")
}
func (a mgmtAPI) DeleteSynchronizedGroups(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteSynchronizedGroups(w, r, id) }, "update:directory_provisionings")
}
func (a mgmtAPI) CreateDirectoryProvisioningConsent(w http.ResponseWriter, r *http.Request, tenant, id string) {
	a.h.CreateDirectoryProvisioningConsent(w, r, tenant, id)
}
