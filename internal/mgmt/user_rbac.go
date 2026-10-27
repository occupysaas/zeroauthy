package mgmt

import "net/http"

func (h *Handlers) GetUserRoles(w http.ResponseWriter, r *http.Request, id string) {
	p, totals, err := rbacPaging(r, "user_roles")
	if err != nil {
		Fail(w, err)
		return
	}
	result, err := h.Store.RBAC().UserRoles(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	writeRBACList(w, "roles", result, p, totals, roleView)
}
func (h *Handlers) userRoles(w http.ResponseWriter, r *http.Request, id string, add bool) {
	ids, err := readRBACIDs(r, "roles")
	if err != nil {
		Fail(w, err)
		return
	}
	if err = h.Store.RBAC().ChangeUserRoles(r.Context(), resolved(r).ID, id, add, ids); err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "change user roles", "id", id)
	w.WriteHeader(204)
}
func (h *Handlers) PostUserRoles(w http.ResponseWriter, r *http.Request, id string) {
	h.userRoles(w, r, id, true)
}
func (h *Handlers) DeleteUserRoles(w http.ResponseWriter, r *http.Request, id string) {
	h.userRoles(w, r, id, false)
}
func (h *Handlers) GetUserPermissions(w http.ResponseWriter, r *http.Request, id string) {
	p, totals, err := rbacPaging(r, "permissions")
	if err != nil {
		Fail(w, err)
		return
	}
	result, err := h.Store.RBAC().UserPermissions(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	writeRBACList(w, "permissions", result, p, totals, permissionView)
}
func (h *Handlers) userPermissions(w http.ResponseWriter, r *http.Request, id string, add bool, status int) {
	keys, err := readPermissionBatch(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if err = h.Store.RBAC().ChangeUserPermissions(r.Context(), resolved(r).ID, id, add, keys); err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "change user permissions", "id", id)
	w.WriteHeader(status)
}
func (h *Handlers) PostUserPermissions(w http.ResponseWriter, r *http.Request, id string) {
	h.userPermissions(w, r, id, true, 201)
}
func (h *Handlers) DeleteUserPermissions(w http.ResponseWriter, r *http.Request, id string) {
	h.userPermissions(w, r, id, false, 204)
}
