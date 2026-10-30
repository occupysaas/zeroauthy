package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clientGrants struct{ s *Store }

func (s *Store) ClientGrants() store.ClientGrants { return clientGrants{s} }

const clientGrantCols = `tenant_id, id, client_id, audience, scopes, created_at, subject_type, origin, allow_all_scopes, organization_usage, allow_any_organization`

func (r clientGrants) Create(ctx context.Context, g *store.ClientGrant) error {
	g = g.WithDefaults()
	scopes, err := toJSON(g.Scopes)
	if err != nil {
		return err
	}
	return r.s.policyWrite(ctx, g.TenantID, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO client_grants (`+clientGrantCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			g.TenantID, g.ID, g.ClientID, g.Audience, scopes, micros(g.CreatedAt), g.SubjectType, g.Origin, g.AllowAllScopes, g.OrganizationUsage, g.AllowAnyOrganization)
		return tx.conflict(err)
	})
}

func (r clientGrants) Find(ctx context.Context, tenantID, clientID, audience, subjectType string) (*store.ClientGrant, error) {
	if err := r.s.policyRead(ctx, tenantID); err != nil {
		return nil, err
	}
	g, err := scanClientGrant(r.s.queryRow(ctx, `SELECT `+clientGrantCols+` FROM client_grants
 WHERE tenant_id = ? AND client_id = ? AND audience = ? AND subject_type = ?`, tenantID, clientID, audience, subjectType))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return g, err
}

func scanClientGrant(row scanner) (*store.ClientGrant, error) {
	var g store.ClientGrant
	var scopes string
	var created int64
	if err := row.Scan(&g.TenantID, &g.ID, &g.ClientID, &g.Audience, &scopes, &created, &g.SubjectType, &g.Origin, &g.AllowAllScopes, &g.OrganizationUsage, &g.AllowAnyOrganization); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &g.Scopes); err != nil {
		return nil, err
	}
	g.CreatedAt = fromMicros(created)
	return &g, nil
}

func (r clientGrants) Update(ctx context.Context, g *store.ClientGrant) error {
	g = g.WithDefaults()
	scopes, err := toJSON(g.Scopes)
	if err != nil {
		return err
	}
	return r.s.policyWrite(ctx, g.TenantID, func(tx *Store) error {
		var clientID, audience, subjectType string
		err := tx.queryRow(ctx, `SELECT client_id, audience, subject_type FROM client_grants WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate,
			g.TenantID, g.ID).Scan(&clientID, &audience, &subjectType)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if clientID != g.ClientID || audience != g.Audience || subjectType != g.SubjectType {
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `UPDATE client_grants SET scopes = ?, created_at = ?, origin = ?, allow_all_scopes = ?, organization_usage = ?, allow_any_organization = ? WHERE tenant_id = ? AND id = ?`,
			scopes, micros(g.CreatedAt), g.Origin, g.AllowAllScopes, g.OrganizationUsage, g.AllowAnyOrganization, g.TenantID, g.ID)
		return err
	})
}

func (r clientGrants) Delete(ctx context.Context, tenantID, id string) error {
	return r.s.policyWrite(ctx, tenantID, func(tx *Store) error {
		res, err := tx.exec(ctx, `DELETE FROM client_grants WHERE tenant_id = ? AND id = ?`, tenantID, id)
		if err != nil {
			return err
		}
		return expectRow(res)
	})
}

func (r clientGrants) List(ctx context.Context, tenantID string, f store.ClientGrantFilter, p store.Page) ([]*store.ClientGrant, int, error) {
	where, args := []string{"tenant_id = ?"}, []any{tenantID}
	for _, c := range []struct{ col, val string }{{"client_id", f.ClientID}, {"audience", f.Audience}, {"subject_type", f.SubjectType}, {"id", f.ID}} {
		if c.val != "" {
			where = append(where, c.col+" = ?")
			args = append(args, c.val)
		}
	}
	if f.AfterID != "" {
		where = append(where, "id"+r.s.d.byteOrder+" > ?")
		args = append(args, f.AfterID)
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM client_grants WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + clientGrantCols + ` FROM client_grants WHERE ` + cond + ` ORDER BY id` + r.s.d.byteOrder
	// Offset and limit are integers built here, never caller text. SQLite
	// and MySQL want a LIMIT with an OFFSET, so "no limit" is the largest
	// BIGINT.
	limit, offset := int64(p.Limit), int64(max(p.Offset, 0))
	if limit <= 0 {
		limit = math.MaxInt64
	}
	q += ` LIMIT ` + strconv.FormatInt(limit, 10) + ` OFFSET ` + strconv.FormatInt(offset, 10)
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*store.ClientGrant
	for rows.Next() {
		g, err := scanClientGrant(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	return out, total, rows.Err()
}
