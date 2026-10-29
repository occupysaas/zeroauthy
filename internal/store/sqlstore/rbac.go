package sqlstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/rbacrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type rbac struct{ s *Store }

func (s *Store) RBAC() store.RBAC { return rbac{s} }

// lockRBAC serializes tenant RBAC writers and snapshots. Every operation uses
// its transaction-bound store, so PostgreSQL READ COMMITTED cannot combine
// settings from one commit with assignments from another.
func (s *Store) lockRBAC(ctx context.Context, tenant string) error {
	var id string
	err := s.queryRow(ctx, `SELECT id FROM tenants WHERE id=?`+s.d.forUpdate, tenant).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}
func (r rbac) atomic(ctx context.Context, tenant string, fn func(rbac) error) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockRBAC(ctx, tenant); err != nil {
			return err
		}
		return fn(rbac{tx})
	})
}
func (r rbac) CreateRole(ctx context.Context, role *store.Role) error {
	if len(rbacrules.NormalizeRole(role)) > 0 || role.ID == "" {
		return store.ErrInvalid
	}
	return r.atomic(ctx, role.TenantID, func(t rbac) error {
		_, err := t.s.exec(ctx, `INSERT INTO rbac_roles (tenant_id,id,name,description) VALUES (?,?,?,?)`, role.TenantID, role.ID, role.Name, role.Description)
		return t.s.conflict(err)
	})
}
func (r rbac) GetRole(ctx context.Context, tenant, id string) (*store.Role, error) {
	if r.s.tx != nil {
		if err := r.s.lockRBAC(ctx, tenant); err != nil {
			return nil, err
		}
	}
	var out store.Role
	err := r.s.queryRow(ctx, `SELECT tenant_id,id,name,description FROM rbac_roles WHERE tenant_id=? AND id=?`, tenant, id).Scan(&out.TenantID, &out.ID, &out.Name, &out.Description)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (r rbac) UpdateRole(ctx context.Context, role *store.Role) error {
	if len(rbacrules.NormalizeRole(role)) > 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, role.TenantID, func(t rbac) error {
		if _, err := t.GetRole(ctx, role.TenantID, role.ID); err != nil {
			return err
		}
		_, err := t.s.exec(ctx, `UPDATE rbac_roles SET name=?,description=? WHERE tenant_id=? AND id=?`, role.Name, role.Description, role.TenantID, role.ID)
		return t.s.conflict(err)
	})
}
func (r rbac) DeleteRole(ctx context.Context, tenant, id string) error {
	return r.atomic(ctx, tenant, func(t rbac) error {
		if _, err := t.GetRole(ctx, tenant, id); err != nil {
			return err
		}
		if _, err := t.s.exec(ctx, `DELETE FROM organization_invitations WHERE tenant_id=? AND id IN (SELECT invitation_id FROM organization_invitation_roles WHERE tenant_id=? AND role_id=?)`, tenant, tenant, id); err != nil {
			return err
		}

		for _, table := range []string{"organization_member_roles", "rbac_user_roles", "rbac_role_permissions"} {
			if _, err := t.s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=? AND role_id=?`, tenant, id); err != nil {
				return err
			}
		}
		_, err := t.s.exec(ctx, `DELETE FROM rbac_roles WHERE tenant_id=? AND id=?`, tenant, id)
		return err
	})
}
func pageRBAC[T any](items []T, p store.RBACPage) (store.RBACResult[T], error) {
	if err := rbacrules.NormalizePage(&p); err != nil {
		return store.RBACResult[T]{}, store.ErrInvalid
	}
	total := len(items)
	start := min(p.Page, total) * p.PerPage
	if start > total {
		start = total
	}
	end := min(start+p.PerPage, total)
	out := append([]T{}, items[start:end]...)
	return store.RBACResult[T]{Items: out, Total: total}, nil
}
func (r rbac) ListRoles(ctx context.Context, tenant string, p store.RBACPage) (store.RBACResult[store.Role], error) {
	rows, err := r.s.query(ctx, `SELECT tenant_id,id,name,description FROM rbac_roles WHERE tenant_id=? ORDER BY id`+r.s.d.byteOrder, tenant)
	if err != nil {
		return store.RBACResult[store.Role]{}, err
	}
	defer rows.Close()
	out := []store.Role{}
	for rows.Next() {
		var role store.Role
		if err := rows.Scan(&role.TenantID, &role.ID, &role.Name, &role.Description); err != nil {
			return store.RBACResult[store.Role]{}, err
		}
		if strings.Contains(strings.ToLower(role.Name), strings.ToLower(p.NameFilter)) {
			out = append(out, role)
		}
	}
	if err := rows.Err(); err != nil {
		return store.RBACResult[store.Role]{}, err
	}
	return pageRBAC(out, p)
}
func (r rbac) permission(ctx context.Context, tenant string, key store.PermissionKey) (*store.ResourceServer, error) {
	api, err := r.s.ResourceServers().GetByIdentifier(ctx, tenant, key.ResourceServerIdentifier)
	if errors.Is(err, store.ErrNotFound) {
		return nil, store.ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if api.IsSystem || slices.Contains([]string{"openid", "profile", "email", "offline_access"}, key.PermissionName) || !slices.ContainsFunc(api.Scopes, func(s store.Scope) bool { return s.Value == key.PermissionName }) {
		return nil, store.ErrInvalid
	}
	return api, nil
}
func (r rbac) changePermissions(ctx context.Context, tenant, id string, role, add bool, keys []store.PermissionKey) error {
	if len(rbacrules.ValidatePermissionKeys(keys)) > 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tenant, func(t rbac) error {
		table, column := "rbac_user_permissions", "user_id"
		if role {
			table, column = "rbac_role_permissions", "role_id"
			if _, err := t.GetRole(ctx, tenant, id); err != nil {
				return err
			}
		} else {
			if _, err := t.s.Users().Get(ctx, tenant, id); err != nil {
				return err
			}
		}
		apis := make([]*store.ResourceServer, len(keys))
		for i, key := range keys {
			api, err := t.permission(ctx, tenant, key)
			if err != nil {
				return err
			}
			apis[i] = api
		}
		seen := map[store.PermissionKey]bool{}
		for i, key := range keys {
			if seen[key] {
				continue
			}
			seen[key] = true
			args := []any{tenant, id, apis[i].ID, key.PermissionName}
			if add {
				var n int
				if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM `+table+` WHERE tenant_id=? AND `+column+`=? AND api_id=? AND permission_name=?`, args...).Scan(&n); err != nil {
					return err
				}
				if n == 0 {
					if _, err := t.s.exec(ctx, `INSERT INTO `+table+` (tenant_id,`+column+`,api_id,permission_name) VALUES (?,?,?,?)`, args...); err != nil {
						return err
					}
				}
			} else {
				if _, err := t.s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=? AND `+column+`=? AND api_id=? AND permission_name=?`, args...); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
func (r rbac) ChangeRolePermissions(ctx context.Context, t, id string, add bool, k []store.PermissionKey) error {
	return r.changePermissions(ctx, t, id, true, add, k)
}
func (r rbac) ChangeUserPermissions(ctx context.Context, t, id string, add bool, k []store.PermissionKey) error {
	return r.changePermissions(ctx, t, id, false, add, k)
}
func validBatch(ids []string) bool {
	return len(ids) > 0 && len(ids) <= 100 && !slices.Contains(ids, "")
}
func (r rbac) changeUserRoles(ctx context.Context, tenant string, userIDs, roleIDs []string, add bool) error {
	if !validBatch(userIDs) || !validBatch(roleIDs) {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tenant, func(t rbac) error {
		for _, id := range userIDs {
			if _, err := t.s.Users().Get(ctx, tenant, id); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return store.ErrInvalid
				}
				return err
			}
		}
		for _, id := range roleIDs {
			if _, err := t.GetRole(ctx, tenant, id); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return store.ErrInvalid
				}
				return err
			}
		}
		for _, uid := range userIDs {
			for _, rid := range roleIDs {
				if add {
					var n int
					if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM rbac_user_roles WHERE tenant_id=? AND user_id=? AND role_id=?`, tenant, uid, rid).Scan(&n); err != nil {
						return err
					}
					if n == 0 {
						if _, err := t.s.exec(ctx, `INSERT INTO rbac_user_roles (tenant_id,user_id,role_id) VALUES (?,?,?)`, tenant, uid, rid); err != nil {
							return err
						}
					}
				} else {
					if _, err := t.s.exec(ctx, `DELETE FROM rbac_user_roles WHERE tenant_id=? AND user_id=? AND role_id=?`, tenant, uid, rid); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}
func (r rbac) ChangeUserRoles(ctx context.Context, tenant, id string, add bool, roles []string) error {
	// Parent absence is 404; absent referenced role is invalid input.
	if _, err := r.s.Users().Get(ctx, tenant, id); err != nil {
		return err
	}
	return r.changeUserRoles(ctx, tenant, []string{id}, roles, add)
}
func (r rbac) AssignRoleUsers(ctx context.Context, tenant, id string, users []string) error {
	if _, err := r.GetRole(ctx, tenant, id); err != nil {
		return err
	}
	return r.changeUserRoles(ctx, tenant, users, []string{id}, true)
}
func (r rbac) UserRoles(ctx context.Context, tenant, id string, p store.RBACPage) (store.RBACResult[store.Role], error) {
	var out store.RBACResult[store.Role]
	err := r.atomic(ctx, tenant, func(t rbac) error {
		if _, err := t.s.Users().Get(ctx, tenant, id); err != nil {
			return err
		}
		rows, err := t.s.query(ctx, `SELECT r.tenant_id,r.id,r.name,r.description FROM rbac_roles r JOIN rbac_user_roles u ON r.tenant_id=u.tenant_id AND r.id=u.role_id WHERE u.tenant_id=? AND u.user_id=? ORDER BY r.id`+t.s.d.byteOrder, tenant, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		items := []store.Role{}
		for rows.Next() {
			var v store.Role
			if err := rows.Scan(&v.TenantID, &v.ID, &v.Name, &v.Description); err != nil {
				return err
			}
			items = append(items, v)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		out, err = pageRBAC(items, p)
		return err
	})
	return out, err
}
func (r rbac) RoleUsers(ctx context.Context, tenant, id string, p store.RBACPage) (store.RBACResult[store.User], error) {
	var out store.RBACResult[store.User]
	err := r.atomic(ctx, tenant, func(t rbac) error {
		if _, err := t.GetRole(ctx, tenant, id); err != nil {
			return err
		}
		checkpoint := p.Take > 0 || p.From != ""
		if err := rbacrules.NormalizePage(&p); err != nil {
			return store.ErrInvalid
		}
		rows, err := t.s.query(ctx, `SELECT user_id FROM rbac_user_roles WHERE tenant_id=? AND role_id=? ORDER BY user_id`+t.s.d.byteOrder, tenant, id)
		if err != nil {
			return err
		}
		ids := []string{}
		for rows.Next() {
			var uid string
			if err := rows.Scan(&uid); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, uid)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		items := []store.User{}
		for _, uid := range ids {
			u, err := t.s.Users().Get(ctx, tenant, uid)
			if err != nil {
				return err
			}
			items = append(items, *u)
		}
		if checkpoint {
			var raw []byte
			if p.From != "" {
				var e error
				raw, e = base64.RawURLEncoding.DecodeString(p.From)
				if e != nil {
					return store.ErrInvalid
				}
				var cursor [3]string
				if json.Unmarshal(raw, &cursor) != nil || cursor[0] != tenant || cursor[1] != id {
					return store.ErrInvalid
				}
				items = slices.DeleteFunc(items, func(u store.User) bool { return u.UserID <= cursor[2] })
			}
			limit := p.Take
			more := len(items) > limit
			if more {
				items = items[:limit]
			}
			out = store.RBACResult[store.User]{Items: items, Total: len(ids)}
			if more {
				raw, _ = json.Marshal([3]string{tenant, id, items[len(items)-1].UserID})
				out.Next = base64.RawURLEncoding.EncodeToString(raw)
			}
			return nil
		}
		out, err = pageRBAC(items, p)
		return err
	})
	return out, err
}

// grants is called while holding the tenant authorization lock. Sources are
// retained separately until permissions are unioned, so direct removal cannot
// erase the same permission inherited from a role.
func (r rbac) grants(ctx context.Context, tenant, id string, role bool) ([]store.PermissionGrant, error) {
	type edge struct{ api, name, sourceID, sourceName string }
	edges := []edge{}
	if role {
		rows, err := r.s.query(ctx, `SELECT api_id,permission_name FROM rbac_role_permissions WHERE tenant_id=? AND role_id=?`, tenant, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e edge
			if err = rows.Scan(&e.api, &e.name); err != nil {
				rows.Close()
				return nil, err
			}
			edges = append(edges, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	} else {
		rows, err := r.s.query(ctx, `SELECT api_id,permission_name FROM rbac_user_permissions WHERE tenant_id=? AND user_id=?`, tenant, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e edge
			if err = rows.Scan(&e.api, &e.name); err != nil {
				rows.Close()
				return nil, err
			}
			edges = append(edges, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		rows, err = r.s.query(ctx, `SELECT p.api_id,p.permission_name,r.id,r.name FROM rbac_role_permissions p JOIN rbac_user_roles u ON p.tenant_id=u.tenant_id AND p.role_id=u.role_id JOIN rbac_roles r ON p.tenant_id=r.tenant_id AND p.role_id=r.id WHERE u.tenant_id=? AND u.user_id=?`, tenant, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var e edge
			if err = rows.Scan(&e.api, &e.name, &e.sourceID, &e.sourceName); err != nil {
				rows.Close()
				return nil, err
			}
			edges = append(edges, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	apis := map[string]*store.ResourceServer{}
	grants := map[store.PermissionKey]*store.PermissionGrant{}
	for _, e := range edges {
		api := apis[e.api]
		if api == nil {
			v, err := r.s.ResourceServers().Get(ctx, tenant, e.api)
			if err != nil {
				return nil, err
			}
			api = v
			apis[e.api] = v
		}
		i := slices.IndexFunc(api.Scopes, func(s store.Scope) bool { return s.Value == e.name })
		if api.IsSystem || i < 0 {
			continue
		}
		key := store.PermissionKey{ResourceServerIdentifier: api.Identifier, PermissionName: e.name}
		g := grants[key]
		if g == nil {
			g = &store.PermissionGrant{Key: key, ResourceServerName: api.Name, Description: api.Scopes[i].Description, Sources: []store.PermissionSource{}}
			grants[key] = g
		}
		if !role {
			source := store.PermissionSource{Type: "direct", ID: id}
			if e.sourceID != "" {
				source = store.PermissionSource{Type: "role", ID: e.sourceID, Name: e.sourceName}
			}
			if !slices.Contains(g.Sources, source) {
				g.Sources = append(g.Sources, source)
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
	slices.SortFunc(out, func(a, b store.PermissionGrant) int {
		if n := strings.Compare(a.Key.ResourceServerIdentifier, b.Key.ResourceServerIdentifier); n != 0 {
			return n
		}
		return strings.Compare(a.Key.PermissionName, b.Key.PermissionName)
	})
	return out, nil
}
func (r rbac) RolePermissions(ctx context.Context, tenant, id string, p store.RBACPage) (store.RBACResult[store.PermissionGrant], error) {
	var out store.RBACResult[store.PermissionGrant]
	err := r.atomic(ctx, tenant, func(t rbac) error {
		if _, e := t.GetRole(ctx, tenant, id); e != nil {
			return e
		}
		items, e := t.grants(ctx, tenant, id, true)
		if e != nil {
			return e
		}
		out, e = pageRBAC(items, p)
		return e
	})
	return out, err
}
func (r rbac) UserPermissions(ctx context.Context, tenant, id string, p store.RBACPage) (store.RBACResult[store.PermissionGrant], error) {
	var out store.RBACResult[store.PermissionGrant]
	err := r.atomic(ctx, tenant, func(t rbac) error {
		if _, e := t.s.Users().Get(ctx, tenant, id); e != nil {
			return e
		}
		items, e := t.grants(ctx, tenant, id, false)
		if e != nil {
			return e
		}
		out, e = pageRBAC(items, p)
		return e
	})
	return out, err
}
func (r rbac) Snapshot(ctx context.Context, tenant, user, audience string) (*store.AuthorizationSnapshot, error) {
	var out *store.AuthorizationSnapshot
	err := r.atomic(ctx, tenant, func(t rbac) error {
		if _, e := t.s.Users().Get(ctx, tenant, user); e != nil {
			return e
		}
		api, e := t.s.ResourceServers().GetByIdentifier(ctx, tenant, audience)
		if e != nil {
			return e
		}
		if api.IsSystem {
			return store.ErrInvalid
		}
		perms, e := t.grants(ctx, tenant, user, false)
		if e != nil {
			return e
		}
		out = &store.AuthorizationSnapshot{API: api, Permissions: []string{}}
		if out.API.TokenDialect == "" {
			out.API.TokenDialect = "access_token"
		}
		for _, p := range perms {
			if p.Key.ResourceServerIdentifier == audience {
				out.Permissions = append(out.Permissions, p.Key.PermissionName)
			}
		}
		slices.Sort(out.Permissions)
		return nil
	})
	return out, err
}

func (s *Store) pruneRBACPermissions(ctx context.Context, tenant, apiID string, scopes []store.Scope) error {
	for _, table := range []string{"rbac_role_permissions", "rbac_user_permissions"} {
		q := `DELETE FROM ` + table + ` WHERE tenant_id=? AND api_id=?`
		args := []any{tenant, apiID}
		if len(scopes) > 0 {
			q += ` AND permission_name NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(scopes)), ",") + `)`
			for _, scope := range scopes {
				args = append(args, scope.Value)
			}
		}
		if _, err := s.exec(ctx, q, args...); err != nil {
			return err
		}
	}
	return nil
}
