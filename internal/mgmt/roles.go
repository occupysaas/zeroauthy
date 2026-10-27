package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/rbacrules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *Handlers) rbacError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		Fail(w, &Error{Status: 404, Code: "inexistent_resource", Message: "The requested resource does not exist"})
	case errors.Is(err, store.ErrConflict):
		Fail(w, &Error{Status: 409, Code: "role_conflict", Message: "The role name is already in use"})
	case errors.Is(err, store.ErrInvalid):
		Fail(w, badBody("invalid role, permission or assignment"))
	default:
		var typed *Error
		if errors.As(err, &typed) {
			Fail(w, typed)
		} else {
			Fail(w, internalError(h, r, "RBAC operation", err))
		}
	}
}

func roleView(v store.Role) map[string]any {
	return map[string]any{"id": v.ID, "name": v.Name, "description": v.Description}
}
func permissionView(v store.PermissionGrant) map[string]any {
	out := map[string]any{"resource_server_identifier": v.Key.ResourceServerIdentifier, "permission_name": v.Key.PermissionName, "resource_server_name": v.ResourceServerName, "description": v.Description}
	if len(v.Sources) > 0 {
		sources := make([]map[string]any, 0, len(v.Sources))
		for _, s := range v.Sources {
			source := map[string]any{"source_type": strings.ToUpper(s.Type)}
			if s.Type == "role" {
				source["source_id"] = s.ID
				source["source_name"] = s.Name
			}
			sources = append(sources, source)
		}
		out["sources"] = sources
	}
	return out
}

// rbacPaging rejects unsupported/deferred query fields before store access.
func rbacPaging(r *http.Request, kind string) (store.RBACPage, bool, error) {
	p := store.RBACPage{}
	allowed := []string{"page", "per_page", "include_totals"}
	if kind == "roles" {
		allowed = append(allowed, "name_filter", "type")
	}
	if kind == "users" {
		allowed = append(allowed, "from", "take")
	}
	for k, vs := range r.URL.Query() {
		if !slices.Contains(allowed, k) || len(vs) != 1 || vs[0] == "" {
			return p, false, badQuery("unsupported or invalid query parameter %q", k)
		}
	}
	page, per, totals, err := Page(r)
	if err != nil {
		return p, false, err
	}
	p.Page, p.PerPage = page, per
	q := r.URL.Query()
	if kind == "roles" {
		p.NameFilter = q.Get("name_filter")
		if q.Has("type") && q.Get("type") != "tenant" {
			return p, false, badQuery("only tenant roles are supported")
		}
	}
	if kind == "users" && (q.Has("from") || q.Has("take")) {
		if q.Has("page") || q.Has("per_page") {
			return p, false, badQuery("checkpoint and offset pagination cannot be combined")
		}
		p.From, p.Take = q.Get("from"), 50
		if q.Has("take") {
			p.Take, err = strconv.Atoi(q.Get("take"))
			if err != nil || p.Take < 1 || p.Take > 100 {
				return p, false, badQuery("take must be 1 to 100")
			}
		}
	}
	return p, totals, nil
}
func writeRBACList[T any](w http.ResponseWriter, name string, result store.RBACResult[T], p store.RBACPage, totals bool, view func(T) map[string]any) {
	items := make([]map[string]any, 0, len(result.Items))
	for _, v := range result.Items {
		items = append(items, view(v))
	}
	if p.Take > 0 || p.From != "" {
		out := map[string]any{name: items}
		if result.Next != "" {
			out["next"] = result.Next
		}
		writeJSON(w, 200, out)
		return
	}
	if totals {
		writeJSON(w, 200, map[string]any{"start": p.Page * p.PerPage, "limit": p.PerPage, "total": result.Total, name: items})
		return
	}
	writeJSON(w, 200, items)
}

func (h *Handlers) GetRoles(w http.ResponseWriter, r *http.Request) {
	p, totals, err := rbacPaging(r, "roles")
	if err != nil {
		Fail(w, err)
		return
	}
	result, err := h.Store.RBAC().ListRoles(r.Context(), resolved(r).ID, p)
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	writeRBACList(w, "roles", result, p, totals, roleView)
}
func (h *Handlers) GetRolesById(w http.ResponseWriter, r *http.Request, id string) {
	v, err := h.Store.RBAC().GetRole(r.Context(), resolved(r).ID, id)
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	writeJSON(w, 200, roleView(*v))
}
func readRole(r *http.Request, role *store.Role, create bool) error {
	body, err := decodeObject(r)
	if err != nil {
		return err
	}
	if create {
		if _, ok := body["name"]; !ok {
			return badBody("name is required")
		}
	}
	for k, raw := range body {
		switch k {
		case "name":
			err = decodeString(raw, &role.Name)
		case "description":
			err = decodeString(raw, &role.Description)
		case "type":
			var v string
			err = decodeString(raw, &v)
			if !create || v != "tenant" {
				return badBody("only tenant roles are supported")
			}
		default:
			return badBody("unknown property %q", k)
		}
		if err != nil {
			return badBody("%s must be a string", k)
		}
	}
	if errs := rbacrules.NormalizeRole(role); len(errs) > 0 {
		return badBody("%v", errors.Join(errs...))
	}
	return nil
}
func (h *Handlers) PostRoles(w http.ResponseWriter, r *http.Request) {
	role := &store.Role{TenantID: resolved(r).ID, ID: "rol_" + secrets.RandomString(18)}
	if err := readRole(r, role, true); err != nil {
		Fail(w, err)
		return
	}
	if err := h.Store.RBAC().CreateRole(r.Context(), role); err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "create role", "id", role.ID)
	writeJSON(w, 200, roleView(*role))
}
func (h *Handlers) PatchRolesById(w http.ResponseWriter, r *http.Request, id string) {
	var out *store.Role
	err := h.Store.WithTx(r.Context(), func(tx store.Store) error {
		role, err := tx.RBAC().GetRole(r.Context(), resolved(r).ID, id)
		if err != nil {
			return err
		}
		if err := readRole(r, role, false); err != nil {
			return err
		}
		if err := tx.RBAC().UpdateRole(r.Context(), role); err != nil {
			return err
		}
		out = role
		return nil
	})
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "update role", "id", id)
	writeJSON(w, 200, roleView(*out))
}
func (h *Handlers) DeleteRolesById(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Store.RBAC().DeleteRole(r.Context(), resolved(r).ID, id); err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "delete role", "id", id)
	w.WriteHeader(200)
}
func (h *Handlers) GetRolePermissions(w http.ResponseWriter, r *http.Request, id string) {
	p, totals, err := rbacPaging(r, "permissions")
	if err != nil {
		Fail(w, err)
		return
	}
	result, err := h.Store.RBAC().RolePermissions(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	writeRBACList(w, "permissions", result, p, totals, permissionView)
}
func readPermissionBatch(r *http.Request) ([]store.PermissionKey, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	if len(body) != 1 || body["permissions"] == nil {
		return nil, badBody("permissions is required")
	}
	var items []map[string]json.RawMessage
	if err := decodeStrict(body["permissions"], &items); err != nil {
		return nil, badBody("permissions must be an array")
	}
	keys := make([]store.PermissionKey, len(items))
	for i, item := range items {
		if len(item) != 2 || decodeString(item["resource_server_identifier"], &keys[i].ResourceServerIdentifier) != nil || decodeString(item["permission_name"], &keys[i].PermissionName) != nil {
			return nil, badBody("permission pairs require resource_server_identifier and permission_name")
		}
	}
	if errs := rbacrules.ValidatePermissionKeys(keys); len(errs) > 0 {
		return nil, badBody("%v", errors.Join(errs...))
	}
	return keys, nil
}
func (h *Handlers) rolePermissions(w http.ResponseWriter, r *http.Request, id string, add bool, status int) {
	keys, err := readPermissionBatch(r)
	if err != nil {
		Fail(w, err)
		return
	}
	if err = h.Store.RBAC().ChangeRolePermissions(r.Context(), resolved(r).ID, id, add, keys); err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "change role permissions", "id", id)
	w.WriteHeader(status)
}
func (h *Handlers) PostRolePermissions(w http.ResponseWriter, r *http.Request, id string) {
	h.rolePermissions(w, r, id, true, 201)
}
func (h *Handlers) DeleteRolePermissions(w http.ResponseWriter, r *http.Request, id string) {
	h.rolePermissions(w, r, id, false, 200)
}
func (h *Handlers) GetRoleUsers(w http.ResponseWriter, r *http.Request, id string) {
	p, totals, err := rbacPaging(r, "users")
	if err != nil {
		Fail(w, err)
		return
	}
	result, err := h.Store.RBAC().RoleUsers(r.Context(), resolved(r).ID, id, p)
	if err != nil {
		h.rbacError(w, r, err)
		return
	}
	writeRBACList(w, "users", result, p, totals, func(u store.User) map[string]any {
		out := map[string]any{"user_id": u.UserID}
		if u.Name != "" {
			out["name"] = u.Name
		}
		if u.Email != "" {
			out["email"] = u.Email
		}
		if u.Picture != "" {
			out["picture"] = u.Picture
		}
		return out
	})
}
func readRBACIDs(r *http.Request, field string) ([]string, error) {
	body, err := decodeObject(r)
	if err != nil {
		return nil, err
	}
	if len(body) != 1 || body[field] == nil {
		return nil, badBody("%s is required", field)
	}
	var ids []string
	if err := decodeStrict(body[field], &ids); err != nil || len(ids) < 1 || len(ids) > 100 {
		return nil, badBody("%s must contain 1 to 100 identifiers", field)
	}
	for _, id := range ids {
		if id == "" {
			return nil, badBody("identifiers must not be empty")
		}
	}
	return ids, nil
}
func (h *Handlers) PostRoleUsers(w http.ResponseWriter, r *http.Request, id string) {
	ids, err := readRBACIDs(r, "users")
	if err != nil {
		Fail(w, err)
		return
	}
	if err = h.Store.RBAC().AssignRoleUsers(r.Context(), resolved(r).ID, id, ids); err != nil {
		h.rbacError(w, r, err)
		return
	}
	h.audit(r, "assign role users", "id", id)
	w.WriteHeader(200)
}
