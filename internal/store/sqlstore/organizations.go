package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type organizations struct{ s *Store }

func (s *Store) Organizations() store.Organizations { return organizations{s} }

// SetOrgLimits overrides the caps so conformance tests can reach them. The
// override is shared by every handle of the Store, including transactions.
func (s *Store) SetOrgLimits(l store.OrgLimits) {
	if s.orgLimits != nil {
		s.orgLimits.Store(&l)
	}
}

func (s *Store) limits() store.OrgLimits {
	if s.orgLimits != nil {
		if l := s.orgLimits.Load(); l != nil {
			return *l
		}
	}
	return orgrules.Limits()
}

// atomic runs fn in one transaction holding the tenant lock that serializes
// Organizations writers with RBAC, user and connection deletes, so a cascade
// cannot miss a row a concurrent writer is adding. A missing tenant is
// ErrNotFound.
func (r organizations) atomic(ctx context.Context, tid string, fn func(organizations) error) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockRBAC(ctx, tid); err != nil {
			return err
		}
		return fn(organizations{tx})
	})
}

const orgCols = `tenant_id, id, name, display_name, branding, metadata, third_party_client_access, created_at, updated_at`

func scanOrg(row scanner) (*store.Organization, error) {
	var o store.Organization
	var branding, metadata sql.NullString
	var created, updated int64
	if err := row.Scan(&o.TenantID, &o.ID, &o.Name, &o.DisplayName, &branding, &metadata, &o.ThirdPartyClientAccess, &created, &updated); err != nil {
		return nil, err
	}
	if branding.Valid {
		if err := fromJSON(branding.String, &o.Branding); err != nil {
			return nil, err
		}
	}
	if metadata.Valid {
		if err := fromJSON(metadata.String, &o.Metadata); err != nil {
			return nil, err
		}
	}
	o.CreatedAt, o.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &o, nil
}

// nullJSON encodes v as JSON text, or NULL when unset.
func nullJSON(v any, unset bool) (any, error) {
	if unset {
		return nil, nil
	}
	return toJSON(v)
}

func orgJSON(o store.Organization) (branding, metadata any, err error) {
	if branding, err = nullJSON(o.Branding, o.Branding == nil); err != nil {
		return nil, nil, err
	}
	metadata, err = nullJSON(o.Metadata, o.Metadata == nil)
	return branding, metadata, err
}

// now is the current time at the precision the database keeps.
func now() time.Time { return fromMicros(micros(time.Now().UTC())) }

func (r organizations) orgExists(ctx context.Context, tid, id string) error {
	var one int
	err := r.s.queryRow(ctx, `SELECT 1 FROM organizations WHERE tenant_id=? AND id=?`, tid, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// checkConnection verifies the connection exists and the flags suit its
// strategy.
func (r organizations) checkConnection(ctx context.Context, tid string, c store.OrganizationConnection) error {
	var strategy string
	err := r.s.queryRow(ctx, `SELECT strategy FROM connections WHERE tenant_id=? AND id=?`, tid, c.ConnectionID).Scan(&strategy)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if orgrules.ValidateConnection(strategy, c) != nil {
		return store.ErrInvalid
	}
	return nil
}

func (r organizations) insertConnection(ctx context.Context, c store.OrganizationConnection) error {
	_, err := r.s.exec(ctx, `INSERT INTO organization_connections (tenant_id,organization_id,connection_id,assign_membership_on_login,show_as_button,is_signup_enabled) VALUES (?,?,?,?,?,?)`,
		c.TenantID, c.OrganizationID, c.ConnectionID, c.AssignMembershipOnLogin, c.ShowAsButton, c.IsSignupEnabled)
	return r.s.conflict(err)
}

func (r organizations) Create(ctx context.Context, o *store.Organization, conns []store.OrganizationConnection) error {
	if o == nil || o.TenantID == "" || !orgrules.ValidID(o.ID) {
		return store.ErrInvalid
	}
	n, err := orgrules.NormalizeOrganization(*o)
	if err != nil {
		return store.ErrInvalid
	}
	branding, metadata, err := orgJSON(n)
	if err != nil {
		return err
	}
	if err := r.atomic(ctx, o.TenantID, func(t organizations) error {
		var taken int
		if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM organizations WHERE tenant_id=? AND (id=? OR name=?)`, n.TenantID, n.ID, n.Name).Scan(&taken); err != nil {
			return err
		}
		if taken > 0 {
			return store.ErrConflict
		}
		var count int
		if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM organizations WHERE tenant_id=?`, n.TenantID).Scan(&count); err != nil {
			return err
		}
		lim := t.s.limits()
		if count >= lim.OrganizationsPerTenant || len(conns) > lim.ConnectionsPerOrganization {
			return store.ErrPrecondition
		}
		seen := map[string]bool{}
		for _, c := range conns {
			if seen[c.ConnectionID] {
				return store.ErrConflict
			}
			seen[c.ConnectionID] = true
			if err := t.checkConnection(ctx, n.TenantID, c); err != nil {
				return err
			}
		}
		if n.CreatedAt.IsZero() {
			n.CreatedAt = now()
		}
		if n.UpdatedAt.IsZero() {
			n.UpdatedAt = n.CreatedAt
		}
		n.CreatedAt, n.UpdatedAt = fromMicros(micros(n.CreatedAt)), fromMicros(micros(n.UpdatedAt))
		if _, err := t.s.exec(ctx, `INSERT INTO organizations (`+orgCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
			n.TenantID, n.ID, n.Name, n.DisplayName, branding, metadata, n.ThirdPartyClientAccess, micros(n.CreatedAt), micros(n.UpdatedAt)); err != nil {
			return t.s.conflict(err)
		}
		for _, c := range conns {
			c.TenantID, c.OrganizationID = n.TenantID, n.ID
			if err := t.insertConnection(ctx, c); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	*o = n
	return nil
}

func (r organizations) Get(ctx context.Context, tid, id string) (*store.Organization, error) {
	o, err := scanOrg(r.s.queryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE tenant_id=? AND id=?`, tid, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return o, err
}

func (r organizations) GetByName(ctx context.Context, tid, name string) (*store.Organization, error) {
	o, err := scanOrg(r.s.queryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE tenant_id=? AND name=?`, tid, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return o, err
}

func (r organizations) queryOrgs(ctx context.Context, q string, args ...any) ([]*store.Organization, error) {
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (r organizations) List(ctx context.Context, tid string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	orgs, err := r.queryOrgs(ctx, `SELECT `+orgCols+` FROM organizations WHERE tenant_id=?`, tid)
	if err != nil {
		return store.OrgResult[store.Organization]{}, err
	}
	return orgrules.PageOrgs(orgs, p, orgrules.Scope("orgs", tid))
}

func (r organizations) Update(ctx context.Context, o *store.Organization) error {
	if o == nil {
		return store.ErrInvalid
	}
	n, err := orgrules.NormalizeOrganization(*o)
	if err != nil {
		return store.ErrInvalid
	}
	branding, metadata, err := orgJSON(n)
	if err != nil {
		return err
	}
	if err := r.atomic(ctx, o.TenantID, func(t organizations) error {
		cur, err := t.Get(ctx, o.TenantID, o.ID)
		if err != nil {
			return err
		}
		var taken int
		if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM organizations WHERE tenant_id=? AND name=? AND id<>?`, n.TenantID, n.Name, n.ID).Scan(&taken); err != nil {
			return err
		}
		if taken > 0 {
			return store.ErrConflict
		}
		n.CreatedAt, n.UpdatedAt = cur.CreatedAt, now()
		_, err = t.s.exec(ctx, `UPDATE organizations SET name=?, display_name=?, branding=?, metadata=?, third_party_client_access=?, updated_at=? WHERE tenant_id=? AND id=?`,
			n.Name, n.DisplayName, branding, metadata, n.ThirdPartyClientAccess, micros(n.UpdatedAt), n.TenantID, n.ID)
		return t.s.conflict(err)
	}); err != nil {
		return err
	}
	*o = n
	return nil
}

func (r organizations) Delete(ctx context.Context, tid, id string) error {
	return r.atomic(ctx, tid, func(t organizations) error {
		if err := t.orgExists(ctx, tid, id); err != nil {
			return err
		}
		for _, table := range []string{"organization_member_roles", "organization_members", "organization_connections"} {
			if _, err := t.s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=? AND organization_id=?`, tid, id); err != nil {
				return err
			}
		}
		_, err := t.s.exec(ctx, `DELETE FROM organizations WHERE tenant_id=? AND id=?`, tid, id)
		return err
	})
}

const orgConnCols = `tenant_id, organization_id, connection_id, assign_membership_on_login, show_as_button, is_signup_enabled`

func scanOrgConn(row scanner) (store.OrganizationConnection, error) {
	var c store.OrganizationConnection
	err := row.Scan(&c.TenantID, &c.OrganizationID, &c.ConnectionID, &c.AssignMembershipOnLogin, &c.ShowAsButton, &c.IsSignupEnabled)
	return c, err
}

func (r organizations) queryConns(ctx context.Context, q string, args ...any) ([]store.OrganizationConnection, error) {
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []store.OrganizationConnection{}
	for rows.Next() {
		c, err := scanOrgConn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r organizations) Connections(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[store.OrganizationConnection], error) {
	if err := r.orgExists(ctx, tid, orgID); err != nil {
		return store.OrgResult[store.OrganizationConnection]{}, err
	}
	conns, err := r.queryConns(ctx, `SELECT `+orgConnCols+` FROM organization_connections WHERE tenant_id=? AND organization_id=?`, tid, orgID)
	if err != nil {
		return store.OrgResult[store.OrganizationConnection]{}, err
	}
	es := make([]orgrules.Entry[store.OrganizationConnection], len(conns))
	for i, c := range conns {
		es[i] = orgrules.Entry[store.OrganizationConnection]{Item: c, ID: c.ConnectionID}
	}
	orgrules.OrderEntries(es, false)
	return orgrules.PageEntries(es, p, orgrules.Scope("conns", tid, orgID), false)
}

func (r organizations) GetConnection(ctx context.Context, tid, orgID, connID string) (*store.OrganizationConnection, error) {
	c, err := scanOrgConn(r.s.queryRow(ctx, `SELECT `+orgConnCols+` FROM organization_connections WHERE tenant_id=? AND organization_id=? AND connection_id=?`, tid, orgID, connID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r organizations) PutConnection(ctx context.Context, c store.OrganizationConnection, create bool) error {
	return r.atomic(ctx, c.TenantID, func(t organizations) error {
		if err := t.orgExists(ctx, c.TenantID, c.OrganizationID); err != nil {
			return err
		}
		if err := t.checkConnection(ctx, c.TenantID, c); err != nil {
			return err
		}
		_, err := t.GetConnection(ctx, c.TenantID, c.OrganizationID, c.ConnectionID)
		exists := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		switch {
		case create && exists:
			return store.ErrConflict
		case !create && !exists:
			return store.ErrNotFound
		}
		if !create {
			_, err := t.s.exec(ctx, `UPDATE organization_connections SET assign_membership_on_login=?, show_as_button=?, is_signup_enabled=? WHERE tenant_id=? AND organization_id=? AND connection_id=?`,
				c.AssignMembershipOnLogin, c.ShowAsButton, c.IsSignupEnabled, c.TenantID, c.OrganizationID, c.ConnectionID)
			return err
		}
		var n int
		if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM organization_connections WHERE tenant_id=? AND organization_id=?`, c.TenantID, c.OrganizationID).Scan(&n); err != nil {
			return err
		}
		if n >= t.s.limits().ConnectionsPerOrganization {
			return store.ErrPrecondition
		}
		return t.insertConnection(ctx, c)
	})
}

func (r organizations) DeleteConnection(ctx context.Context, tid, orgID, connID string) error {
	return r.atomic(ctx, tid, func(t organizations) error {
		if err := t.orgExists(ctx, tid, orgID); err != nil {
			return err
		}
		var one int
		err := t.s.queryRow(ctx, `SELECT 1 FROM connections WHERE tenant_id=? AND id=?`, tid, connID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = t.s.exec(ctx, `DELETE FROM organization_connections WHERE tenant_id=? AND organization_id=? AND connection_id=?`, tid, orgID, connID)
		return err
	})
}

func (r organizations) ConnectionsByConnection(ctx context.Context, tid, connID string) ([]store.OrganizationConnection, error) {
	return r.queryConns(ctx, `SELECT `+orgConnCols+` FROM organization_connections WHERE tenant_id=? AND connection_id=? ORDER BY organization_id`+r.s.d.byteOrder, tid, connID)
}

// pageIDs pages the single ID column col of from, filtered by where, in byte
// order, in SQL: member lists can be large. Offset and checkpoint styles
// match orgrules.PageIDs.
func (s *Store) pageIDs(ctx context.Context, p store.OrgPage, scope, from, col, where string, args ...any) (store.OrgResult[string], error) {
	mode, err := orgrules.NormalizePage(&p)
	if err != nil {
		return store.OrgResult[string]{}, store.ErrInvalid
	}
	out := store.OrgResult[string]{Items: []string{}}
	q := `SELECT ` + col + ` FROM ` + from + ` WHERE ` + where
	order := ` ORDER BY ` + col + s.d.byteOrder
	limit := 0
	if mode == orgrules.Offset {
		if err := s.queryRow(ctx, `SELECT COUNT(*) FROM `+from+` WHERE `+where, args...).Scan(&out.Total); err != nil {
			return out, err
		}
		q += order + ` LIMIT ` + strconv.Itoa(p.PerPage) + ` OFFSET ` + strconv.Itoa(p.Page*p.PerPage)
	} else {
		if p.From != "" {
			c, err := orgrules.DecodeCursor(p.From, scope, p.Sort)
			if err != nil {
				return out, store.ErrInvalid
			}
			q += ` AND ` + col + s.d.byteOrder + ` > ?`
			args = append(slices.Clone(args), c.ID)
		}
		limit = p.Take
		q += order + ` LIMIT ` + strconv.Itoa(p.Take+1)
	}
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return out, err
		}
		out.Items = append(out.Items, id)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if limit > 0 && len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.Next = orgrules.EncodeCursor(orgrules.Cursor{Scope: scope, Sort: p.Sort, ID: out.Items[limit-1]})
	}
	return out, nil
}

func (r organizations) Members(ctx context.Context, tid, orgID string, p store.OrgPage) (store.OrgResult[string], error) {
	if err := r.orgExists(ctx, tid, orgID); err != nil {
		return store.OrgResult[string]{}, err
	}
	return r.s.pageIDs(ctx, p, orgrules.Scope("members", tid, orgID), `organization_members`, `user_id`, `tenant_id=? AND organization_id=?`, tid, orgID)
}

func (r organizations) AddMembers(ctx context.Context, tid, orgID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tid, func(t organizations) error {
		if err := t.orgExists(ctx, tid, orgID); err != nil {
			return err
		}
		for _, id := range userIDs {
			var one int
			err := t.s.queryRow(ctx, `SELECT 1 FROM users WHERE tenant_id=? AND user_id=?`, tid, id).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return store.ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		for _, id := range userIDs {
			var n int
			if err := t.s.queryRow(ctx, `SELECT COUNT(*) FROM organization_members WHERE tenant_id=? AND organization_id=? AND user_id=?`, tid, orgID, id).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				if _, err := t.s.exec(ctx, `INSERT INTO organization_members (tenant_id,organization_id,user_id) VALUES (?,?,?)`, tid, orgID, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (r organizations) RemoveMembers(ctx context.Context, tid, orgID string, userIDs []string) error {
	if len(userIDs) == 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tid, func(t organizations) error {
		if err := t.orgExists(ctx, tid, orgID); err != nil {
			return err
		}
		// Role assignments stay so that re-adding the member restores them.
		for _, id := range userIDs {
			if _, err := t.s.exec(ctx, `DELETE FROM organization_members WHERE tenant_id=? AND organization_id=? AND user_id=?`, tid, orgID, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r organizations) isMember(ctx context.Context, tid, orgID, userID string) (bool, error) {
	var n int
	err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM organization_members WHERE tenant_id=? AND organization_id=? AND user_id=?`, tid, orgID, userID).Scan(&n)
	return n > 0, err
}

func (r organizations) IsMember(ctx context.Context, tid, orgID, userID string) (bool, error) {
	if err := r.orgExists(ctx, tid, orgID); err != nil {
		return false, err
	}
	return r.isMember(ctx, tid, orgID, userID)
}

func (r organizations) UserOrganizations(ctx context.Context, tid, userID string, p store.OrgPage) (store.OrgResult[store.Organization], error) {
	var one int
	err := r.s.queryRow(ctx, `SELECT 1 FROM users WHERE tenant_id=? AND user_id=?`, tid, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.OrgResult[store.Organization]{}, store.ErrNotFound
	}
	if err != nil {
		return store.OrgResult[store.Organization]{}, err
	}
	orgs, err := r.queryOrgs(ctx, `SELECT `+orgCols+` FROM organizations WHERE tenant_id=? AND id IN (SELECT organization_id FROM organization_members WHERE tenant_id=? AND user_id=?)`, tid, tid, userID)
	if err != nil {
		return store.OrgResult[store.Organization]{}, err
	}
	return orgrules.PageOrgs(orgs, p, orgrules.Scope("user-orgs", tid, userID))
}

// member reports ErrNotFound unless the organization exists and userID
// belongs to it.
func (r organizations) member(ctx context.Context, tid, orgID, userID string) error {
	if err := r.orgExists(ctx, tid, orgID); err != nil {
		return err
	}
	in, err := r.isMember(ctx, tid, orgID, userID)
	if err != nil {
		return err
	}
	if !in {
		return store.ErrNotFound
	}
	return nil
}

func (r organizations) MemberRoles(ctx context.Context, tid, orgID, userID string, p store.OrgPage) (store.OrgResult[string], error) {
	if err := r.member(ctx, tid, orgID, userID); err != nil {
		return store.OrgResult[string]{}, err
	}
	return r.s.pageIDs(ctx, p, orgrules.Scope("member-roles", tid, orgID, userID), `organization_member_roles`, `role_id`, `tenant_id=? AND organization_id=? AND user_id=?`, tid, orgID, userID)
}

func (r organizations) ChangeMemberRoles(ctx context.Context, tid, orgID, userID string, add bool, roleIDs []string) error {
	if len(roleIDs) == 0 {
		return store.ErrInvalid
	}
	return r.atomic(ctx, tid, func(t organizations) error {
		if err := t.member(ctx, tid, orgID, userID); err != nil {
			return err
		}
		if !add {
			for _, id := range roleIDs {
				if _, err := t.s.exec(ctx, `DELETE FROM organization_member_roles WHERE tenant_id=? AND organization_id=? AND user_id=? AND role_id=?`, tid, orgID, userID, id); err != nil {
					return err
				}
			}
			return nil
		}
		for _, id := range roleIDs {
			var one int
			err := t.s.queryRow(ctx, `SELECT 1 FROM rbac_roles WHERE tenant_id=? AND id=?`, tid, id).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return store.ErrNotFound
			}
			if err != nil {
				return err
			}
		}
		rows, err := t.s.query(ctx, `SELECT role_id FROM organization_member_roles WHERE tenant_id=? AND organization_id=? AND user_id=?`, tid, orgID, userID)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			have[id] = true
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
		var missing []string
		for _, id := range roleIDs {
			if !have[id] {
				have[id] = true
				missing = append(missing, id)
			}
		}
		if len(have) > t.s.limits().RolesPerMember {
			return store.ErrPrecondition
		}
		for _, id := range missing {
			if _, err := t.s.exec(ctx, `INSERT INTO organization_member_roles (tenant_id,organization_id,user_id,role_id) VALUES (?,?,?,?)`, tid, orgID, userID, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r organizations) RoleMembers(ctx context.Context, tid, orgID, roleID string, p store.OrgPage) (store.OrgResult[string], error) {
	if err := r.orgExists(ctx, tid, orgID); err != nil {
		return store.OrgResult[string]{}, err
	}
	var one int
	err := r.s.queryRow(ctx, `SELECT 1 FROM rbac_roles WHERE tenant_id=? AND id=?`, tid, roleID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return store.OrgResult[string]{}, store.ErrNotFound
	}
	if err != nil {
		return store.OrgResult[string]{}, err
	}
	// Checkpoint style only: offset parameters are ignored.
	p.Page, p.PerPage, p.IncludeTotals = 0, 0, false
	if p.From == "" && p.Take == 0 {
		p.Take = orgrules.Limit("take_default")
	}
	// Only current members count: a removed member keeps role rows.
	return r.s.pageIDs(ctx, p, orgrules.Scope("role-members", tid, orgID, roleID),
		`organization_member_roles r JOIN organization_members m ON m.tenant_id=r.tenant_id AND m.organization_id=r.organization_id AND m.user_id=r.user_id`,
		`r.user_id`, `r.tenant_id=? AND r.organization_id=? AND r.role_id=?`, tid, orgID, roleID)
}
