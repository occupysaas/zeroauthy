package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type authCodes struct{ s *Store }

func (s *Store) AuthCodes() store.AuthCodes { return authCodes{s} }

const authCodeCols = `tenant_id, code_hash, client_id, redirect_uri, user_id, session_id, scopes, audience, nonce,
 code_challenge, code_challenge_method, auth_time, expires_at, created_at, used_at, replayed_at`

func (r authCodes) Create(ctx context.Context, c *store.AuthCode) error {
	scopes, err := toJSON(c.Scopes)
	if err != nil {
		return err
	}
	// Retried on deadlock: on MySQL an INSERT can be the victim of a cycle
	// with DeleteExpired's range DELETE (gap locks).
	return r.s.atomicRetry(ctx, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO auth_codes (`+authCodeCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.TenantID, c.CodeHash, c.ClientID, c.RedirectURI, c.UserID, c.SessionID, scopes, c.Audience, c.Nonce,
			c.CodeChallenge, c.CodeChallengeMethod, micros(c.AuthTime), micros(c.ExpiresAt), micros(c.CreatedAt),
			nullMicros(c.UsedAt), nullMicros(c.ReplayedAt))
		return tx.conflict(err)
	})
}

// Consume claims the code with one conditional UPDATE by primary key, so
// concurrent callers see exactly one success without a SELECT … FOR UPDATE.
// A loser (or a later caller) records the first replay with a second
// conditional UPDATE. Both run in one transaction with the read-back, so the
// returned record is the state this call produced. A replay commits (the
// replay time is part of the contract) and then reports ErrAlreadyUsed.
func (r authCodes) Consume(ctx context.Context, tenantID, codeHash string, at time.Time) (*store.AuthCode, error) {
	var out *store.AuthCode
	var replay bool
	err := r.s.atomicRetry(ctx, func(tx *Store) error {
		out, replay = nil, false
		res, err := tx.exec(ctx, `UPDATE auth_codes SET used_at = ? WHERE tenant_id = ? AND code_hash = ? AND used_at IS NULL`,
			micros(at), tenantID, codeHash)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			replay = true
			if _, err := tx.exec(ctx, `UPDATE auth_codes SET replayed_at = ? WHERE tenant_id = ? AND code_hash = ? AND used_at IS NOT NULL AND replayed_at IS NULL`,
				micros(at), tenantID, codeHash); err != nil {
				return err
			}
		}
		c, err := authCodes{tx}.Get(ctx, tenantID, codeHash)
		if err != nil {
			return err
		}
		if c.UsedAt == nil { // created after our UPDATE looked: absent as far as this call is concerned
			return store.ErrNotFound
		}
		out = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	if replay {
		return out, store.ErrAlreadyUsed
	}
	return out, nil
}

func (r authCodes) Get(ctx context.Context, tenantID, codeHash string) (*store.AuthCode, error) {
	c, err := scanAuthCode(r.s.queryRow(ctx, `SELECT `+authCodeCols+` FROM auth_codes WHERE tenant_id = ? AND code_hash = ?`, tenantID, codeHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r authCodes) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM auth_codes WHERE expires_at <= ?`, micros(before)))
		return err
	})
	return n, err
}

func scanAuthCode(row scanner) (*store.AuthCode, error) {
	var c store.AuthCode
	var scopes string
	var authAt, exp, created int64
	var used, replayed sql.NullInt64
	if err := row.Scan(&c.TenantID, &c.CodeHash, &c.ClientID, &c.RedirectURI, &c.UserID, &c.SessionID, &scopes,
		&c.Audience, &c.Nonce, &c.CodeChallenge, &c.CodeChallengeMethod, &authAt, &exp, &created, &used, &replayed); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &c.Scopes); err != nil {
		return nil, err
	}
	c.AuthTime, c.ExpiresAt, c.CreatedAt = fromMicros(authAt), fromMicros(exp), fromMicros(created)
	c.UsedAt, c.ReplayedAt = fromNullMicros(used), fromNullMicros(replayed)
	return &c, nil
}
