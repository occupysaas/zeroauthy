package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// directory is Plan 37c's SCIM and group state (migration 0046).
type directory struct{ s *Store }

func (s *Store) Directory() store.Directory { return directory{s} }
func (s *Store) DirectorySupported() bool   { return true }

func optTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMicros(v.Int64)
	return &t
}

func (r directory) CreateSCIMConfig(ctx context.Context, c *store.SCIMConfig) error {
	mapping, err := toJSON(c.Mapping)
	if err != nil {
		return err
	}
	_, err = r.s.write(ctx, nil, `INSERT INTO scim_configurations (tenant_id, connection_id, user_id_attribute, mapping, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		c.TenantID, c.ConnectionID, c.UserIDAttribute, mapping, micros(c.CreatedAt), micros(c.UpdatedAt))
	return r.s.conflict(err)
}

func scanSCIMConfig(row scanner) (*store.SCIMConfig, error) {
	var c store.SCIMConfig
	var mapping string
	var created, updated int64
	if err := row.Scan(&c.TenantID, &c.ConnectionID, &c.UserIDAttribute, &mapping, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(mapping, &c.Mapping); err != nil {
		return nil, err
	}
	c.CreatedAt, c.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &c, nil
}

const scimConfigCols = `tenant_id, connection_id, user_id_attribute, mapping, created_at, updated_at`

func (r directory) GetSCIMConfig(ctx context.Context, tid, conn string) (*store.SCIMConfig, error) {
	c, err := scanSCIMConfig(r.s.queryRow(ctx, `SELECT `+scimConfigCols+` FROM scim_configurations WHERE tenant_id = ? AND connection_id = ?`, tid, conn))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r directory) UpdateSCIMConfig(ctx context.Context, c *store.SCIMConfig) error {
	mapping, err := toJSON(c.Mapping)
	if err != nil {
		return err
	}
	res, err := r.s.write(ctx, nil, `UPDATE scim_configurations SET user_id_attribute = ?, mapping = ?, updated_at = ? WHERE tenant_id = ? AND connection_id = ?`,
		c.UserIDAttribute, mapping, micros(c.UpdatedAt), c.TenantID, c.ConnectionID)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r directory) DeleteSCIMConfig(ctx context.Context, tid, conn string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `DELETE FROM scim_configurations WHERE tenant_id = ? AND connection_id = ?`, tid, conn)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		_, err = tx.exec(ctx, `DELETE FROM scim_tokens WHERE tenant_id = ? AND connection_id = ?`, tid, conn)
		return err
	})
}

func (r directory) ListSCIMConfigs(ctx context.Context, tid string) ([]*store.SCIMConfig, error) {
	rows, err := r.s.query(ctx, `SELECT `+scimConfigCols+` FROM scim_configurations WHERE tenant_id = ? ORDER BY created_at, connection_id`+r.s.d.byteOrder, tid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.SCIMConfig{}
	for rows.Next() {
		c, err := scanSCIMConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

const scimTokenCols = `tenant_id, id, connection_id, token_hash, scopes, created_at, expires_at, last_used_at`

func scanSCIMToken(row scanner) (*store.SCIMToken, error) {
	var t store.SCIMToken
	var scopes string
	var created int64
	var expires, used sql.NullInt64
	if err := row.Scan(&t.TenantID, &t.ID, &t.ConnectionID, &t.Hash, &scopes, &created, &expires, &used); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &t.Scopes); err != nil {
		return nil, err
	}
	t.CreatedAt, t.ExpiresAt, t.LastUsedAt = fromMicros(created), optTime(expires), optTime(used)
	return &t, nil
}

func (r directory) CreateSCIMToken(ctx context.Context, t *store.SCIMToken) error {
	scopes, err := toJSON(t.Scopes)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		// Serialize token creation per connection on its configuration row.
		var one int
		err := tx.queryRow(ctx, `SELECT 1 FROM scim_configurations WHERE tenant_id = ? AND connection_id = ?`+tx.d.forUpdate, t.TenantID, t.ConnectionID).Scan(&one)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var active int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM scim_tokens WHERE tenant_id = ? AND connection_id = ? AND (expires_at IS NULL OR expires_at > ?)`,
			t.TenantID, t.ConnectionID, micros(t.CreatedAt)).Scan(&active); err != nil {
			return err
		}
		if active >= store.MaxActiveSCIMTokens {
			return store.ErrSCIMTokenLimit
		}
		_, err = tx.exec(ctx, `INSERT INTO scim_tokens (`+scimTokenCols+`) VALUES (?,?,?,?,?,?,?,?)`,
			t.TenantID, t.ID, t.ConnectionID, t.Hash, scopes, micros(t.CreatedAt), nullMicros(t.ExpiresAt), nullMicros(t.LastUsedAt))
		return tx.conflict(err)
	})
}

func (r directory) ListSCIMTokens(ctx context.Context, tid, conn string) ([]*store.SCIMToken, error) {
	rows, err := r.s.query(ctx, `SELECT `+scimTokenCols+` FROM scim_tokens WHERE tenant_id = ? AND connection_id = ? ORDER BY created_at, id`+r.s.d.byteOrder, tid, conn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.SCIMToken{}
	for rows.Next() {
		t, err := scanSCIMToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r directory) DeleteSCIMToken(ctx context.Context, tid, conn, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM scim_tokens WHERE tenant_id = ? AND connection_id = ? AND id = ?`, tid, conn, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r directory) UseSCIMToken(ctx context.Context, tid, hash string, now time.Time) (*store.SCIMToken, error) {
	var out *store.SCIMToken
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `UPDATE scim_tokens SET last_used_at = ? WHERE tenant_id = ? AND token_hash = ?`, micros(now), tid, hash)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		out, err = scanSCIMToken(tx.queryRow(ctx, `SELECT `+scimTokenCols+` FROM scim_tokens WHERE tenant_id = ? AND token_hash = ?`, tid, hash))
		return err
	})
	return out, err
}

const groupCols = `tenant_id, id, connection_id, name, external_id, created_at, updated_at`

func scanGroup(row scanner) (*store.Group, error) {
	var g store.Group
	var created, updated int64
	if err := row.Scan(&g.TenantID, &g.ID, &g.ConnectionID, &g.Name, &g.ExternalID, &created, &updated); err != nil {
		return nil, err
	}
	g.CreatedAt, g.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &g, nil
}

func (r directory) CreateGroup(ctx context.Context, g *store.Group) error {
	_, err := r.s.write(ctx, nil, `INSERT INTO directory_groups (`+groupCols+`) VALUES (?,?,?,?,?,?,?)`,
		g.TenantID, g.ID, g.ConnectionID, g.Name, g.ExternalID, micros(g.CreatedAt), micros(g.UpdatedAt))
	return r.s.conflict(err)
}

func (r directory) GetGroup(ctx context.Context, tid, id string) (*store.Group, error) {
	g, err := scanGroup(r.s.queryRow(ctx, `SELECT `+groupCols+` FROM directory_groups WHERE tenant_id = ? AND id = ?`, tid, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return g, err
}

func (r directory) UpdateGroup(ctx context.Context, g *store.Group) error {
	res, err := r.s.write(ctx, nil, `UPDATE directory_groups SET name = ?, external_id = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`,
		g.Name, g.ExternalID, micros(g.UpdatedAt), g.TenantID, g.ID)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r directory) DeleteGroup(ctx context.Context, tid, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, `DELETE FROM directory_groups WHERE tenant_id = ? AND id = ?`, tid, id)
		if err != nil {
			return err
		}
		if err := expectRow(res); err != nil {
			return err
		}
		return tx.dropGroupRows(ctx, `tenant_id = ? AND group_id = ?`, tid, id)
	})
}

// dropGroupRows deletes membership and role rows matching cond.
func (s *Store) dropGroupRows(ctx context.Context, cond string, args ...any) error {
	for _, table := range []string{"directory_group_members", "directory_group_roles"} {
		if _, err := s.exec(ctx, `DELETE FROM `+table+` WHERE `+cond, args...); err != nil {
			return err
		}
	}
	return nil
}

// likePrefix escapes a LIKE prefix pattern (escape character !).
func likePrefix(s string) string {
	r := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")
	return r.Replace(strings.ToLower(s)) + "%"
}

func (r directory) ListGroups(ctx context.Context, tid string, f store.GroupFilter, p store.Page) ([]*store.Group, int, error) {
	where, args := []string{"tenant_id = ?"}, []any{tid}
	for col, v := range map[string]string{"connection_id": f.ConnectionID, "name": f.Name, "external_id": f.ExternalID} {
		if v != "" {
			where = append(where, col+" = ?")
			args = append(args, v)
		}
	}
	if f.NamePrefix != "" {
		where = append(where, `LOWER(name) LIKE ? ESCAPE '!'`)
		args = append(args, likePrefix(f.NamePrefix))
	}
	if len(f.IDs) > 0 {
		where = append(where, "id IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.IDs)), ",")+")")
		for _, id := range f.IDs {
			args = append(args, id)
		}
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM directory_groups WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.s.query(ctx, `SELECT `+groupCols+` FROM directory_groups WHERE `+cond+` ORDER BY created_at, id`+r.s.d.byteOrder+pageClause(p), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*store.Group
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}

func (r directory) UpdateGroupMembers(ctx context.Context, tid, gid string, add, remove []string, replace bool, now time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var one int
		if err := tx.queryRow(ctx, `SELECT 1 FROM directory_groups WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate, tid, gid).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
		drop := remove
		if replace {
			current, err := tx.memberIDs(ctx, tid, gid)
			if err != nil {
				return err
			}
			keep := map[string]bool{}
			for _, u := range add {
				keep[u] = true
			}
			drop = nil
			for _, u := range current {
				if !keep[u] {
					drop = append(drop, u)
				}
			}
		}
		for _, u := range drop {
			if _, err := tx.exec(ctx, `DELETE FROM directory_group_members WHERE tenant_id = ? AND group_id = ? AND user_id = ?`, tid, gid, u); err != nil {
				return err
			}
		}
		current, err := tx.memberIDs(ctx, tid, gid)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for _, u := range current {
			have[u] = true
		}
		for _, u := range add {
			if have[u] {
				continue
			}
			have[u] = true
			if _, err := tx.exec(ctx, `INSERT INTO directory_group_members (tenant_id, group_id, user_id, created_at) VALUES (?,?,?,?)`, tid, gid, u, micros(now)); err != nil {
				return tx.conflict(err)
			}
		}
		return nil
	})
}

func (s *Store) memberIDs(ctx context.Context, tid, gid string) ([]string, error) {
	rows, err := s.query(ctx, `SELECT user_id FROM directory_group_members WHERE tenant_id = ? AND group_id = ?`, tid, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r directory) members(ctx context.Context, cond string, p store.Page, args ...any) ([]store.GroupMember, error) {
	rows, err := r.s.query(ctx, `SELECT group_id, user_id, created_at FROM directory_group_members WHERE `+cond+
		` ORDER BY created_at, user_id`+r.s.d.byteOrder+`, group_id`+r.s.d.byteOrder+pageClause(p), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.GroupMember{}
	for rows.Next() {
		var m store.GroupMember
		var created int64
		if err := rows.Scan(&m.GroupID, &m.UserID, &created); err != nil {
			return nil, err
		}
		m.CreatedAt = fromMicros(created)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r directory) ListGroupMembers(ctx context.Context, tid, gid string, p store.Page) ([]store.GroupMember, int, error) {
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM directory_group_members WHERE tenant_id = ? AND group_id = ?`, tid, gid).Scan(&total); err != nil {
		return nil, 0, err
	}
	out, err := r.members(ctx, `tenant_id = ? AND group_id = ?`, p, tid, gid)
	return out, total, err
}

func (r directory) ListUserGroups(ctx context.Context, tid, uid string) ([]store.GroupMember, error) {
	return r.members(ctx, `tenant_id = ? AND user_id = ?`, store.Page{}, tid, uid)
}

func (r directory) AddGroupRoles(ctx context.Context, tid, gid, org string, roles []string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		for _, role := range roles {
			var one int
			err := tx.queryRow(ctx, `SELECT 1 FROM directory_group_roles WHERE tenant_id = ? AND group_id = ? AND role_id = ? AND organization_id = ?`, tid, gid, role, org).Scan(&one)
			if err == nil {
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := tx.exec(ctx, `INSERT INTO directory_group_roles (tenant_id, group_id, role_id, organization_id) VALUES (?,?,?,?)`, tid, gid, role, org); err != nil {
				return tx.conflict(err)
			}
		}
		return nil
	})
}

func (r directory) RemoveGroupRoles(ctx context.Context, tid, gid, org string, roles []string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		for _, role := range roles {
			if _, err := tx.exec(ctx, `DELETE FROM directory_group_roles WHERE tenant_id = ? AND group_id = ? AND role_id = ? AND organization_id = ?`, tid, gid, role, org); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r directory) ListGroupRoles(ctx context.Context, tid, gid, role, org string) ([]store.GroupRole, error) {
	where, args := []string{"tenant_id = ?", "organization_id = ?"}, []any{tid, org}
	if gid != "" {
		where, args = append(where, "group_id = ?"), append(args, gid)
	}
	if role != "" {
		where, args = append(where, "role_id = ?"), append(args, role)
	}
	rows, err := r.s.query(ctx, `SELECT group_id, role_id, organization_id FROM directory_group_roles WHERE `+strings.Join(where, " AND ")+
		` ORDER BY group_id`+r.s.d.byteOrder+`, role_id`+r.s.d.byteOrder, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.GroupRole{}
	for rows.Next() {
		var g store.GroupRole
		if err := rows.Scan(&g.GroupID, &g.RoleID, &g.OrganizationID); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Cascades, run inside the owning delete's transaction.

func (s *Store) dropDirectoryUser(ctx context.Context, tid, uid string) error {
	_, err := s.exec(ctx, `DELETE FROM directory_group_members WHERE tenant_id = ? AND user_id = ?`, tid, uid)
	return err
}

func (s *Store) dropDirectoryRole(ctx context.Context, tid, role string) error {
	_, err := s.exec(ctx, `DELETE FROM directory_group_roles WHERE tenant_id = ? AND role_id = ?`, tid, role)
	return err
}

func (s *Store) dropDirectoryOrganization(ctx context.Context, tid, org string) error {
	_, err := s.exec(ctx, `DELETE FROM directory_group_roles WHERE tenant_id = ? AND organization_id = ?`, tid, org)
	return err
}

func (s *Store) dropDirectoryConnection(ctx context.Context, tid, conn string) error {
	for _, q := range []string{
		`DELETE FROM directory_group_members WHERE tenant_id = ? AND group_id IN (SELECT id FROM directory_groups WHERE tenant_id = ? AND connection_id = ?)`,
		`DELETE FROM directory_group_roles WHERE tenant_id = ? AND group_id IN (SELECT id FROM directory_groups WHERE tenant_id = ? AND connection_id = ?)`,
	} {
		if _, err := s.exec(ctx, q, tid, tid, conn); err != nil {
			return err
		}
	}
	for _, table := range []string{"directory_groups", "scim_tokens", "scim_configurations", "directory_synchronized_groups", "directory_provisionings"} {
		if _, err := s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ? AND connection_id = ?`, tid, conn); err != nil {
			return err
		}
	}
	return nil
}
