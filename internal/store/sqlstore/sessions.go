package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type sessions struct{ s *Store }

func (s *Store) Sessions() store.Sessions { return sessions{s} }

const sessionCols = `tenant_id, id, token_hash, user_id, connection, authenticated_at, client_ids, expires_at, idle_expires_at, created_at`

func (r sessions) Create(ctx context.Context, s *store.LoginSession) error {
	clients, err := toJSON(s.ClientIDs)
	if err != nil {
		return err
	}
	_, err = r.s.exec(ctx, `INSERT INTO sessions (`+sessionCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		s.TenantID, s.ID, s.TokenHash, s.UserID, s.Connection, micros(s.AuthenticatedAt), clients,
		micros(s.ExpiresAt), micros(s.IdleExpiresAt), micros(s.CreatedAt))
	return r.s.conflict(err)
}

func (r sessions) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.LoginSession, error) {
	var s store.LoginSession
	var clients string
	var authAt, exp, idle, created int64
	err := r.s.queryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE tenant_id = ? AND token_hash = ?`, tenantID, tokenHash).
		Scan(&s.TenantID, &s.ID, &s.TokenHash, &s.UserID, &s.Connection, &authAt, &clients, &exp, &idle, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(clients, &s.ClientIDs); err != nil {
		return nil, err
	}
	s.AuthenticatedAt, s.ExpiresAt, s.IdleExpiresAt, s.CreatedAt = fromMicros(authAt), fromMicros(exp), fromMicros(idle), fromMicros(created)
	return &s, nil
}

func (r sessions) Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	res, err := r.s.exec(ctx, `UPDATE sessions SET idle_expires_at = ? WHERE tenant_id = ? AND id = ?`, micros(idleExpiresAt), tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r sessions) AddClient(ctx context.Context, tenantID, id, clientID string) error {
	return r.s.atomic(ctx, func(tx *Store) error {
		var raw string
		err := tx.queryRow(ctx, `SELECT client_ids FROM sessions WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate, tenantID, id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		var ids []string
		if err := fromJSON(raw, &ids); err != nil {
			return err
		}
		if slices.Contains(ids, clientID) {
			return nil
		}
		enc, err := toJSON(append(ids, clientID))
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE sessions SET client_ids = ? WHERE tenant_id = ? AND id = ?`, enc, tenantID, id)
		return err
	})
}

func (r sessions) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := r.s.exec(ctx, `DELETE FROM sessions WHERE expires_at <= ? OR idle_expires_at <= ?`, micros(before), micros(before))
	return affected(res, err)
}

func (r sessions) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	res, err := r.s.exec(ctx, `DELETE FROM sessions WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
	return affected(res, err)
}

func (r sessions) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.s.exec(ctx, `DELETE FROM sessions WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func affected(res sql.Result, err error) (int, error) {
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
