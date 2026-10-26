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

const authTxnCols = `tenant_id, id, cookie_hash, csrf_token, client_id, params, expires_at, created_at, hosted_state, hosted_revision, origin`

func (r authTransactions) Create(ctx context.Context, t *store.AuthTransaction) error {
	params, err := toJSON(t.Params)
	if err != nil {
		return err
	}
	hosted, err := toJSON(t.HostedState)
	if err != nil {
		return err
	}
	_, err = r.s.write(ctx, nil, `INSERT INTO auth_transactions (`+authTxnCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		t.TenantID, t.ID, t.CookieHash, t.CSRFToken, t.ClientID, params, micros(t.ExpiresAt), micros(t.CreatedAt), hosted, t.HostedState.Revision, t.Origin)
	return r.s.conflict(err)
}

func (r authTransactions) Get(ctx context.Context, tenantID, id string) (*store.AuthTransaction, error) {
	var t store.AuthTransaction
	var params string
	var hosted sql.NullString
	var rev int64
	var exp, created int64
	err := r.s.queryRow(ctx, `SELECT `+authTxnCols+` FROM auth_transactions WHERE tenant_id = ? AND id = ?`, tenantID, id).
		Scan(&t.TenantID, &t.ID, &t.CookieHash, &t.CSRFToken, &t.ClientID, &params, &exp, &created, &hosted, &rev, &t.Origin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := fromJSON(params, &t.Params); err != nil {
		return nil, err
	}
	if hosted.Valid && hosted.String != "" {
		if err := fromJSON(hosted.String, &t.HostedState); err != nil {
			return nil, err
		}
	}
	t.HostedState.Revision = rev
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
	if tenantID == "" || id == "" || expectedRevision < 0 {
		return store.ErrInvalid
	}
	next = next.Clone()
	next.Revision = expectedRevision + 1
	raw, err := toJSON(next)
	if err != nil {
		return store.ErrInvalid
	}
	res, err := r.s.write(ctx, nil, `UPDATE auth_transactions SET hosted_state=?,hosted_revision=? WHERE tenant_id=? AND id=? AND hosted_revision=? AND expires_at>?`, raw, next.Revision, tenantID, id, expectedRevision, micros(now))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var expiry int64
	err = r.s.queryRow(ctx, `SELECT expires_at FROM auth_transactions WHERE tenant_id=? AND id=?`, tenantID, id).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	if expiry <= micros(now) {
		return store.ErrNotFound
	}
	return store.ErrConflict
}
