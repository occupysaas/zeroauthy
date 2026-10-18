package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type userGrants struct{ s *Store }

func (s *Store) UserGrants() store.UserGrants { return userGrants{s} }

const userGrantCols = `tenant_id, id, client_id, user_id, audience, scopes, created_at, updated_at`

func scanUserGrant(row scanner) (*store.UserGrant, error) {
	var g store.UserGrant
	var scopes string
	var created, updated int64
	if err := row.Scan(&g.TenantID, &g.ID, &g.ClientID, &g.UserID, &g.Audience, &scopes, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &g.Scopes); err != nil {
		return nil, err
	}
	g.CreatedAt, g.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &g, nil
}

func (r userGrants) Find(ctx context.Context, tenantID, clientID, userID, audience string) (*store.UserGrant, error) {
	g, err := scanUserGrant(r.s.queryRow(ctx, `SELECT `+userGrantCols+` FROM user_grants
 WHERE tenant_id = ? AND client_id = ? AND user_id = ? AND audience = ?`, tenantID, clientID, userID, audience))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return g, err
}

// Upsert is SELECT ... FOR UPDATE then UPDATE or INSERT in one transaction.
// A concurrent first insert of the same key loses on the unique key; the
// loser retries once and then finds the row to update.
func (r userGrants) Upsert(ctx context.Context, g *store.UserGrant) (*store.UserGrant, error) {
	scopes, err := toJSON(g.Scopes)
	if err != nil {
		return nil, err
	}
	var out *store.UserGrant
	attempt := func() error {
		return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
			old, err := scanUserGrant(tx.queryRow(ctx, `SELECT `+userGrantCols+` FROM user_grants
 WHERE tenant_id = ? AND client_id = ? AND user_id = ? AND audience = ?`+tx.d.forUpdate, g.TenantID, g.ClientID, g.UserID, g.Audience))
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if _, err := tx.exec(ctx, `INSERT INTO user_grants (`+userGrantCols+`) VALUES (?,?,?,?,?,?,?,?)`,
					g.TenantID, g.ID, g.ClientID, g.UserID, g.Audience, scopes, micros(g.CreatedAt), micros(g.UpdatedAt)); err != nil {
					return tx.conflict(err)
				}
				out = &store.UserGrant{TenantID: g.TenantID, ID: g.ID, ClientID: g.ClientID, UserID: g.UserID,
					Audience: g.Audience, Scopes: append([]string(nil), g.Scopes...), CreatedAt: fromMicros(micros(g.CreatedAt)), UpdatedAt: fromMicros(micros(g.UpdatedAt))}
				return nil
			case err != nil:
				return err
			}
			if _, err := tx.exec(ctx, `UPDATE user_grants SET scopes = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`,
				scopes, micros(g.UpdatedAt), old.TenantID, old.ID); err != nil {
				return err
			}
			old.Scopes, old.UpdatedAt = append([]string(nil), g.Scopes...), fromMicros(micros(g.UpdatedAt))
			out = old
			return nil
		})
	}
	err = attempt()
	if errors.Is(err, store.ErrConflict) {
		err = attempt()
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r userGrants) ListByUser(ctx context.Context, tenantID, userID string) ([]*store.UserGrant, error) {
	rows, err := r.s.query(ctx, `SELECT `+userGrantCols+` FROM user_grants WHERE tenant_id = ? AND user_id = ? ORDER BY client_id, audience`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.UserGrant
	for rows.Next() {
		g, err := scanUserGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r userGrants) ListByAudience(ctx context.Context, tenantID, audience string) ([]*store.UserGrant, error) {
	rows, err := r.s.query(ctx, `SELECT `+userGrantCols+` FROM user_grants WHERE tenant_id = ? AND audience = ? ORDER BY id`+r.s.d.byteOrder, tenantID, audience)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.UserGrant
	for rows.Next() {
		g, err := scanUserGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (r userGrants) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM user_grants WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r userGrants) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	res, err := r.s.write(ctx, nil, `DELETE FROM user_grants WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
