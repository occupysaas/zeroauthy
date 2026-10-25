package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type resourceServers struct{ s *Store }

func (s *Store) ResourceServers() store.ResourceServers { return resourceServers{s} }

const resourceServerCols = `tenant_id, id, identifier, name, scopes, signing_alg, token_lifetime, allow_offline_access, created_at,
 skip_consent_for_verifiable_first_party_clients, user_policy, client_policy, is_system, origin, token_lifetime_for_web`

func (r resourceServers) Create(ctx context.Context, rs *store.ResourceServer) error {
	args, err := resourceServerArgs(rs)
	if err != nil {
		return err
	}
	_, err = r.s.write(ctx, nil, `INSERT INTO resource_servers (`+resourceServerCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
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
	res, err := r.s.write(ctx, nil, `UPDATE resource_servers SET identifier=?, name=?, scopes=?, signing_alg=?, token_lifetime=?,
 allow_offline_access=?, created_at=?, skip_consent_for_verifiable_first_party_clients=?, user_policy=?,
 client_policy=?, is_system=?, origin=?, token_lifetime_for_web=? WHERE tenant_id=? AND id=?`, append(args[2:], rs.TenantID, rs.ID)...)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r resourceServers) Delete(ctx context.Context, tenantID, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		rs, err := resourceServers{tx}.Get(ctx, tenantID, id)
		if err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM resource_servers WHERE tenant_id = ? AND id = ?`, tenantID, id); err != nil {
			return err
		}
		// A tenant whose default audience was this API has none now (D-0041).
		if _, err := tx.exec(ctx, `UPDATE tenants SET default_audience = '' WHERE id = ? AND default_audience = ?`, tenantID, rs.Identifier); err != nil {
			return err
		}
		for _, table := range []string{"client_grants", "user_grants", "refresh_tokens"} {
			if _, err := tx.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = ? AND audience = ?`, tenantID, rs.Identifier); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r resourceServers) List(ctx context.Context, tenantID string) ([]*store.ResourceServer, error) {
	rows, err := r.s.query(ctx, `SELECT `+resourceServerCols+` FROM resource_servers WHERE tenant_id = ? ORDER BY created_at, id`+r.s.d.byteOrder, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.ResourceServer
	for rows.Next() {
		rs, err := scanResourceServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

func (r resourceServers) RenameSystem(ctx context.Context, tenantID, identifier, name string) error {
	res, err := r.s.write(ctx, nil, `UPDATE resource_servers SET name = ? WHERE tenant_id = ? AND identifier = ? AND is_system = ?`, name, tenantID, identifier, true)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	// Some SQL drivers report changed rows rather than matched rows. A
	// repeated startup upgrade with the same name is still a successful no-op.
	_, err = r.one(ctx, `SELECT `+resourceServerCols+` FROM resource_servers WHERE tenant_id = ? AND identifier = ? AND is_system = ?`, tenantID, identifier, true)
	if errors.Is(err, store.ErrNotFound) {
		return store.ErrNotFound
	}
	return err
}

func (r resourceServers) one(ctx context.Context, q string, args ...any) (*store.ResourceServer, error) {
	rs, err := scanResourceServer(r.s.queryRow(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return rs, err
}

func scanResourceServer(row scanner) (*store.ResourceServer, error) {
	var rs store.ResourceServer
	var scopes string
	var created int64
	err := row.Scan(&rs.TenantID, &rs.ID, &rs.Identifier, &rs.Name, &scopes, &rs.SigningAlg,
		&rs.TokenLifetime, &rs.AllowOfflineAccess, &created, &rs.SkipConsentForVerifiableFirstPartyClients,
		&rs.SubjectTypeAuthorization.User, &rs.SubjectTypeAuthorization.Client, &rs.IsSystem, &rs.Origin, &rs.TokenLifetimeForWeb)
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
		rs.AllowOfflineAccess, micros(rs.CreatedAt), rs.SkipConsentForVerifiableFirstPartyClients,
		rs.SubjectTypeAuthorization.User, rs.SubjectTypeAuthorization.Client, rs.IsSystem, rs.Origin, rs.TokenLifetimeForWeb}, nil
}
