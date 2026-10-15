package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type resourceServers struct{ s *Store }

func (s *Store) ResourceServers() store.ResourceServers { return resourceServers{s} }

const resourceServerCols = `tenant_id, id, identifier, name, scopes, signing_alg, token_lifetime, allow_offline_access, created_at`

func (r resourceServers) Create(ctx context.Context, rs *store.ResourceServer) error {
	args, err := resourceServerArgs(rs)
	if err != nil {
		return err
	}
	_, err = r.s.exec(ctx, `INSERT INTO resource_servers (`+resourceServerCols+`) VALUES (?,?,?,?,?,?,?,?,?)`, args...)
	return r.s.conflict(err)
}

func (r resourceServers) Get(ctx context.Context, tenantID, id string) (*store.ResourceServer, error) {
	return r.one(ctx, `SELECT `+resourceServerCols+` FROM resource_servers WHERE tenant_id = ? AND id = ?`, tenantID, id)
}

func (r resourceServers) GetByIdentifier(ctx context.Context, tenantID, identifier string) (*store.ResourceServer, error) {
	return r.one(ctx, `SELECT `+resourceServerCols+` FROM resource_servers WHERE tenant_id = ? AND identifier = ?`, tenantID, identifier)
}

func (r resourceServers) Update(ctx context.Context, rs *store.ResourceServer) error {
	args, err := resourceServerArgs(rs)
	if err != nil {
		return err
	}
	res, err := r.s.exec(ctx, `UPDATE resource_servers SET identifier=?, name=?, scopes=?, signing_alg=?, token_lifetime=?,
 allow_offline_access=?, created_at=? WHERE tenant_id=? AND id=?`, append(args[2:], rs.TenantID, rs.ID)...)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r resourceServers) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.s.exec(ctx, `DELETE FROM resource_servers WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r resourceServers) one(ctx context.Context, q string, args ...any) (*store.ResourceServer, error) {
	var rs store.ResourceServer
	var scopes string
	var created int64
	err := r.s.queryRow(ctx, q, args...).Scan(&rs.TenantID, &rs.ID, &rs.Identifier, &rs.Name, &scopes, &rs.SigningAlg,
		&rs.TokenLifetime, &rs.AllowOfflineAccess, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &rs.Scopes); err != nil {
		return nil, err
	}
	rs.CreatedAt = fromMicros(created)
	return &rs, nil
}

func resourceServerArgs(rs *store.ResourceServer) ([]any, error) {
	scopes, err := toJSON(rs.Scopes)
	if err != nil {
		return nil, err
	}
	return []any{rs.TenantID, rs.ID, rs.Identifier, rs.Name, scopes, rs.SigningAlg, rs.TokenLifetime,
		rs.AllowOfflineAccess, micros(rs.CreatedAt)}, nil
}
