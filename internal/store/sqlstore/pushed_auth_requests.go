package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type pushedAuthRequests struct{ s *Store }

func (s *Store) PushedAuthRequests() store.PushedAuthRequests { return pushedAuthRequests{s} }

const pushedAuthRequestCols = `tenant_id, id_hash, client_id, params, expires_at, created_at, used_at`

func (r pushedAuthRequests) Create(ctx context.Context, p *store.PushedAuthRequest) error {
	params, err := toJSON(p.Params)
	if err != nil {
		return err
	}
	// Retried on deadlock: on MySQL an INSERT can be the victim of a cycle
	// with DeleteExpired's range DELETE (gap locks).
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO pushed_auth_requests (`+pushedAuthRequestCols+`) VALUES (?,?,?,?,?,?,?)`,
			p.TenantID, p.IDHash, p.ClientID, params, micros(p.ExpiresAt), micros(p.CreatedAt), nullMicros(p.UsedAt))
		return tx.conflict(err)
	})
}

// Consume claims the request with one conditional UPDATE by primary key, so
// concurrent callers see exactly one success. The read-back runs in the
// same transaction, so the returned record is the state this call saw.
func (r pushedAuthRequests) Consume(ctx context.Context, tenantID, idHash string, at time.Time) (*store.PushedAuthRequest, error) {
	var out *store.PushedAuthRequest
	var used bool
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out, used = nil, false
		res, err := tx.exec(ctx, `UPDATE pushed_auth_requests SET used_at = ? WHERE tenant_id = ? AND id_hash = ? AND used_at IS NULL`,
			micros(at), tenantID, idHash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		used = n == 0
		p, err := pushedAuthRequests{tx}.Get(ctx, tenantID, idHash)
		if err != nil {
			return err
		}
		if p.UsedAt == nil { // created after our UPDATE looked: absent as far as this call is concerned
			return store.ErrNotFound
		}
		out = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	if used {
		return out, store.ErrAlreadyUsed
	}
	return out, nil
}

func (r pushedAuthRequests) Get(ctx context.Context, tenantID, idHash string) (*store.PushedAuthRequest, error) {
	p, err := scanPushedAuthRequest(r.s.queryRow(ctx, `SELECT `+pushedAuthRequestCols+` FROM pushed_auth_requests WHERE tenant_id = ? AND id_hash = ?`, tenantID, idHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return p, err
}

func (r pushedAuthRequests) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM pushed_auth_requests WHERE expires_at <= ?`, micros(before)))
		return err
	})
	return n, err
}

func scanPushedAuthRequest(row scanner) (*store.PushedAuthRequest, error) {
	var p store.PushedAuthRequest
	var params string
	var exp, created int64
	var used sql.NullInt64
	if err := row.Scan(&p.TenantID, &p.IDHash, &p.ClientID, &params, &exp, &created, &used); err != nil {
		return nil, err
	}
	if err := fromJSON(params, &p.Params); err != nil {
		return nil, err
	}
	p.ExpiresAt, p.CreatedAt, p.UsedAt = fromMicros(exp), fromMicros(created), fromNullMicros(used)
	return &p, nil
}
