package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type authTransactions struct{ s *Store }

func (s *Store) AuthTransactions() store.AuthTransactions { return authTransactions{s} }

const authTxnCols = `tenant_id, id, cookie_hash, csrf_token, client_id, params, expires_at, created_at`

func (r authTransactions) Create(ctx context.Context, t *store.AuthTransaction) error {
	params, err := toJSON(t.Params)
	if err != nil {
		return err
	}
	_, err = r.s.write(ctx, nil, `INSERT INTO auth_transactions (`+authTxnCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		t.TenantID, t.ID, t.CookieHash, t.CSRFToken, t.ClientID, params, micros(t.ExpiresAt), micros(t.CreatedAt))
	return r.s.conflict(err)
}

func (r authTransactions) Get(ctx context.Context, tenantID, id string) (*store.AuthTransaction, error) {
	var t store.AuthTransaction
	var params string
	var exp, created int64
	err := r.s.queryRow(ctx, `SELECT `+authTxnCols+` FROM auth_transactions WHERE tenant_id = ? AND id = ?`, tenantID, id).
		Scan(&t.TenantID, &t.ID, &t.CookieHash, &t.CSRFToken, &t.ClientID, &params, &exp, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(params, &t.Params); err != nil {
		return nil, err
	}
	t.ExpiresAt, t.CreatedAt = fromMicros(exp), fromMicros(created)
	return &t, nil
}

func (r authTransactions) Delete(ctx context.Context, tenantID, id string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM auth_transactions WHERE tenant_id = ? AND id = ?`, tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r authTransactions) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	res, err := r.s.write(ctx, r.s.sweep(), `DELETE FROM auth_transactions WHERE expires_at <= ?`, micros(before))
	return affected(res, err)
}

func (r authTransactions) CompareAndSwapHosted(ctx context.Context, tenantID, id string, expectedRevision int64, next store.HostedLoginState, now time.Time) error {
	return store.ErrHostedLoginRepositoryUnavailable
}
