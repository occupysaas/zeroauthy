package memory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/rbacrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type rbac struct{ s *Store }
type permissionEdge struct {
	tenant, owner string
	permission    store.PermissionKey
}
type memberEdge struct{ tenant, user, role string }

func (s *Store) RBAC() store.RBAC         { return rbac{s} }
func cloneRole(r *store.Role) *store.Role { v := *r; return &v }
func (r rbac) CreateRole(_ context.Context, v *store.Role) error {
	if len(rbacrules.NormalizeRole(v)) > 0 || v.ID == "" || v.TenantID == "" {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.roles[key{v.TenantID, v.ID}]; ok {
		return store.ErrConflict
	}
	for _, old := range r.s.roles {
		if old.TenantID == v.TenantID && old.Name == v.Name {
			return store.ErrConflict
		}
	}
	r.s.roles[key{v.TenantID, v.ID}] = cloneRole(v)
	return nil
}
func (r rbac) GetRole(_ context.Context, tid, id string) (*store.Role, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.roles[key{tid, id}]
	if v == nil {
		return nil, store.ErrNotFound
	}
	return cloneRole(v), nil
}
func (r rbac) UpdateRole(_ context.Context, v *store.Role) error {
	if len(rbacrules.NormalizeRole(v)) > 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.roles[key{v.TenantID, v.ID}] == nil {
		return store.ErrNotFound
	}
	for _, old := range r.s.roles {
		if old.TenantID == v.TenantID && old.ID != v.ID && old.Name == v.Name {
			return store.ErrConflict
		}
	}
	r.s.roles[key{v.TenantID, v.ID}] = cloneRole(v)
	return nil
}
func (r rbac) DeleteRole(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.roles[key{tid, id}] == nil {
		return store.ErrNotFound
	}
	delete(r.s.roles, key{tid, id})
	r.s.cleanupOrgRole(tid, id)
	for k := range r.s.rolePermissions {
		if k.tenant == tid && k.owner == id {
			delete(r.s.rolePermissions, k)
		}
	}
	for k := range r.s.roleMembers {
		if k.tenant == tid && k.role == id {
			delete(r.s.roleMembers, k)
		}
	}
	return nil
}
func pageRBAC[T any](items []T, p store.RBACPage) (store.RBACResult[T], error) {
	if err := rbacrules.NormalizePage(&p); err != nil {
		return store.RBACResult[T]{}, store.ErrInvalid
	}
	total := len(items)
	start := total
	// Division avoids integer overflow for arbitrarily large page input.
	if p.Page <= total/p.PerPage {
		start = p.Page * p.PerPage
	}
	end := start + min(p.PerPage, total-start)
	out := append([]T{}, items[start:end]...)
	return store.RBACResult[T]{Items: out, Total: total}, nil
}
func (r rbac) ListRoles(_ context.Context, tid string, p store.RBACPage) (store.RBACResult[store.Role], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	items := []store.Role{}
	for _, v := range r.s.roles {
		if v.TenantID == tid && strings.Contains(strings.ToLower(v.Name), strings.ToLower(p.NameFilter)) {
			items = append(items, *v)
		}
	}
	slices.SortFunc(items, func(a, b store.Role) int { return strings.Compare(a.ID, b.ID) })
	return pageRBAC(items, p)
}
func (r rbac) permission(tid string, k store.PermissionKey) (store.PermissionGrant, error) {
	for _, api := range r.s.resourceServers {
		if api.TenantID == tid && api.Identifier == k.ResourceServerIdentifier {
			if api.IsSystem {
				return store.PermissionGrant{}, store.ErrInvalid
			}
			for _, scope := range api.Scopes {
				if scope.Value == k.PermissionName && !protocolPermission(scope.Value) {
					return store.PermissionGrant{Key: k, ResourceServerName: api.Name, Description: scope.Description}, nil
				}
			}
		}
	}
	return store.PermissionGrant{}, store.ErrInvalid
}
func protocolPermission(s string) bool {
	return slices.Contains([]string{"openid", "profile", "email", "offline_access"}, s)
}
func sortPermissions(v []store.PermissionGrant) {
	slices.SortFunc(v, func(a, b store.PermissionGrant) int {
		if n := strings.Compare(a.Key.ResourceServerIdentifier, b.Key.ResourceServerIdentifier); n != 0 {
			return n
		}
		return strings.Compare(a.Key.PermissionName, b.Key.PermissionName)
	})
}
func (r rbac) RolePermissions(_ context.Context, tid, id string, p store.RBACPage) (store.RBACResult[store.PermissionGrant], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.roles[key{tid, id}] == nil {
		return store.RBACResult[store.PermissionGrant]{}, store.ErrNotFound
	}
	items := []store.PermissionGrant{}
	for k := range r.s.rolePermissions {
		if k.tenant == tid && k.owner == id {
			v, err := r.permission(tid, k.permission)
			if err != nil {
				return store.RBACResult[store.PermissionGrant]{}, err
			}
			items = append(items, v)
		}
	}
	sortPermissions(items)
	return pageRBAC(items, p)
}
func (r rbac) ChangeRolePermissions(_ context.Context, tid, id string, add bool, keys []store.PermissionKey) error {
	if len(rbacrules.ValidatePermissionKeys(keys)) > 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.roles[key{tid, id}] == nil {
		return store.ErrNotFound
	}
	for _, k := range keys {
		if _, err := r.permission(tid, k); err != nil {
			return err
		}
	}
	for _, k := range keys {
		edge := permissionEdge{tid, id, k}
		if add {
			r.s.rolePermissions[edge] = true
		} else {
			delete(r.s.rolePermissions, edge)
		}
	}
	return nil
}
func validBatch(ids []string) bool {
	if len(ids) < 1 || len(ids) > 100 {
		return false
	}
	for _, id := range ids {
		if id == "" {
			return false
		}
	}
	return true
}
func (r rbac) AssignRoleUsers(_ context.Context, tid, id string, ids []string) error {
	if !validBatch(ids) {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.roles[key{tid, id}] == nil {
		return store.ErrNotFound
	}
	for _, uid := range ids {
		if r.s.users[key{tid, uid}] == nil {
			return store.ErrInvalid
		}
	}
	for _, uid := range ids {
		r.s.roleMembers[memberEdge{tid, uid, id}] = true
	}
	return nil
}
func (r rbac) ChangeUserRoles(_ context.Context, tid, uid string, add bool, ids []string) error {
	if !validBatch(ids) {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{tid, uid}] == nil {
		return store.ErrNotFound
	}
	for _, id := range ids {
		if r.s.roles[key{tid, id}] == nil {
			return store.ErrInvalid
		}
	}
	for _, id := range ids {
		k := memberEdge{tid, uid, id}
		if add {
			r.s.roleMembers[k] = true
		} else {
			delete(r.s.roleMembers, k)
		}
	}
	return nil
}
func (r rbac) UserRoles(_ context.Context, tid, uid string, p store.RBACPage) (store.RBACResult[store.Role], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.users[key{tid, uid}] == nil {
		return store.RBACResult[store.Role]{}, store.ErrNotFound
	}
	items := []store.Role{}
	for k := range r.s.roleMembers {
		if k.tenant == tid && k.user == uid {
			if v := r.s.roles[key{tid, k.role}]; v != nil {
				items = append(items, *v)
			}
		}
	}
	slices.SortFunc(items, func(a, b store.Role) int { return strings.Compare(a.ID, b.ID) })
	return pageRBAC(items, p)
}
func (r rbac) RoleUsers(_ context.Context, tid, id string, p store.RBACPage) (store.RBACResult[store.User], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.roles[key{tid, id}] == nil {
		return store.RBACResult[store.User]{}, store.ErrNotFound
	}
	items := []store.User{}
	for k := range r.s.roleMembers {
		if k.tenant == tid && k.role == id {
			if u := r.s.users[key{tid, k.user}]; u != nil {
				items = append(items, *cloneUser(u))
			}
		}
	}
	slices.SortFunc(items, func(a, b store.User) int { return strings.Compare(a.UserID, b.UserID) })
	if p.From == "" && p.Take == 0 {
		return pageRBAC(items, p)
	}
	if err := rbacrules.NormalizePage(&p); err != nil {
		return store.RBACResult[store.User]{}, store.ErrInvalid
	}
	after := ""
	if p.From != "" {
		raw, err := base64.RawURLEncoding.DecodeString(p.From)
		var binding []string
		if err != nil || json.Unmarshal(raw, &binding) != nil || len(binding) != 3 || binding[0] != tid || binding[1] != id {
			return store.RBACResult[store.User]{}, store.ErrInvalid
		}
		after = binding[2]
	}
	total := len(items)
	filtered := []store.User{}
	for _, u := range items {
		if u.UserID > after {
			filtered = append(filtered, u)
		}
	}
	out := store.RBACResult[store.User]{Total: total, Items: filtered[:min(len(filtered), p.Take)]}
	if len(filtered) > p.Take {
		raw, _ := json.Marshal([]string{tid, id, out.Items[len(out.Items)-1].UserID})
		out.Next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, nil
}
func (r rbac) ChangeUserPermissions(_ context.Context, tid, uid string, add bool, keys []store.PermissionKey) error {
	if len(rbacrules.ValidatePermissionKeys(keys)) > 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{tid, uid}] == nil {
		return store.ErrNotFound
	}
	for _, k := range keys {
		if _, err := r.permission(tid, k); err != nil {
			return err
		}
	}
	for _, k := range keys {
		e := permissionEdge{tid, uid, k}
		if add {
			r.s.userPermissions[e] = true
		} else {
			delete(r.s.userPermissions, e)
		}
	}
	return nil
}
func (r rbac) effective(tid, uid string) ([]store.PermissionGrant, error) {
	grants := map[store.PermissionKey]*store.PermissionGrant{}
	add := func(k store.PermissionKey, source store.PermissionSource) error {
		v := grants[k]
		if v == nil {
			p, err := r.permission(tid, k)
			if err != nil {
				return err
			}
			v = &p
			grants[k] = v
		}
		v.Sources = append(v.Sources, source)
		return nil
	}
	for k := range r.s.userPermissions {
		if k.tenant == tid && k.owner == uid {
			if err := add(k.permission, store.PermissionSource{Type: "direct"}); err != nil {
				return nil, err
			}
		}
	}
	for m := range r.s.roleMembers {
		if m.tenant != tid || m.user != uid {
			continue
		}
		role := r.s.roles[key{tid, m.role}]
		if role == nil {
			return nil, fmt.Errorf("RBAC role missing")
		}
		for k := range r.s.rolePermissions {
			if k.tenant == tid && k.owner == m.role {
				if err := add(k.permission, store.PermissionSource{Type: "role", ID: role.ID, Name: role.Name}); err != nil {
					return nil, err
				}
			}
		}
	}
	out := []store.PermissionGrant{}
	for _, g := range grants {
		slices.SortFunc(g.Sources, func(a, b store.PermissionSource) int {
			if n := strings.Compare(a.Type, b.Type); n != 0 {
				return n
			}
			return strings.Compare(a.ID, b.ID)
		})
		out = append(out, *g)
	}
	sortPermissions(out)
	return out, nil
}
func (r rbac) UserPermissions(_ context.Context, tid, uid string, p store.RBACPage) (store.RBACResult[store.PermissionGrant], error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.users[key{tid, uid}] == nil {
		return store.RBACResult[store.PermissionGrant]{}, store.ErrNotFound
	}
	items, err := r.effective(tid, uid)
	if err != nil {
		return store.RBACResult[store.PermissionGrant]{}, err
	}
	return pageRBAC(items, p)
}
func (r rbac) Snapshot(_ context.Context, tid, uid, aud string) (*store.AuthorizationSnapshot, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.users[key{tid, uid}] == nil {
		return nil, store.ErrNotFound
	}
	var api *store.ResourceServer
	for _, v := range r.s.resourceServers {
		if v.TenantID == tid && v.Identifier == aud {
			api = cloneResourceServer(v)
		}
	}
	if api == nil {
		return nil, store.ErrNotFound
	}
	if api.IsSystem {
		return nil, store.ErrInvalid
	}
	permissions, err := r.effective(tid, uid)
	if err != nil {
		return nil, err
	}
	out := &store.AuthorizationSnapshot{API: api, Permissions: []string{}}
	for _, v := range permissions {
		if v.Key.ResourceServerIdentifier == aud {
			out.Permissions = append(out.Permissions, v.Key.PermissionName)
		}
	}
	return out, nil
}

// cleanupRBACAPI is called while holding the store write lock.
func (s *Store) cleanupRBACAPI(tid, aud string, scopes []store.Scope) {
	valid := map[string]bool{}
	for _, v := range scopes {
		valid[v.Value] = true
	}
	for k := range s.rolePermissions {
		if k.tenant == tid && k.permission.ResourceServerIdentifier == aud && !valid[k.permission.PermissionName] {
			delete(s.rolePermissions, k)
		}
	}
	for k := range s.userPermissions {
		if k.tenant == tid && k.permission.ResourceServerIdentifier == aud && !valid[k.permission.PermissionName] {
			delete(s.userPermissions, k)
		}
	}
}
func (s *Store) cleanupRBACUser(tid, uid string) {
	for k := range s.roleMembers {
		if k.tenant == tid && k.user == uid {
			delete(s.roleMembers, k)
		}
	}
	for k := range s.userPermissions {
		if k.tenant == tid && k.owner == uid {
			delete(s.userPermissions, k)
		}
	}
}
