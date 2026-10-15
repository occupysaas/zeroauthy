package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clientGrants struct{ s *Store }

func (s *Store) ClientGrants() store.ClientGrants { return clientGrants{s} }

func (r clientGrants) Create(ctx context.Context, g *store.ClientGrant) error {
	scopes, err := toJSON(g.Scopes)
	if err != nil {
		return err
	}
	_, err = r.s.exec(ctx, `INSERT INTO client_grants (tenant_id, id, client_id, audience, scopes, created_at) VALUES (?,?,?,?,?,?)`,
		g.TenantID, g.ID, g.ClientID, g.Audience, scopes, micros(g.CreatedAt))
	return r.s.conflict(err)
}

func (r clientGrants) Find(ctx context.Context, tenantID, clientID, audience string) (*store.ClientGrant, error) {
	var g store.ClientGrant
	var scopes string
	var created int64
	err := r.s.queryRow(ctx, `SELECT tenant_id, id, client_id, audience, scopes, created_at FROM client_grants
 WHERE tenant_id = ? AND client_id = ? AND audience = ?`, tenantID, clientID, audience).
		Scan(&g.TenantID, &g.ID, &g.ClientID, &g.Audience, &scopes, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &g.Scopes); err != nil {
		return nil, err
	}
	g.CreatedAt = fromMicros(created)
	return &g, nil
}

func (r clientGrants) Update(ctx context.Context, g *store.ClientGrant) error {
	scopes, err := toJSON(g.Scopes)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, func(tx *Store) error {
		var clientID, audience string
		err := tx.queryRow(ctx, `SELECT client_id, audience FROM client_grants WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate,
			g.TenantID, g.ID).Scan(&clientID, &audience)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if clientID != g.ClientID || audience != g.Audience {
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `UPDATE client_grants SET scopes = ?, created_at = ? WHERE tenant_id = ? AND id = ?`,
			scopes, micros(g.CreatedAt), g.TenantID, g.ID)
		return err
	})
}

func (r clientGrants) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.s.exec(ctx, `DELETE FROM client_grants WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}
