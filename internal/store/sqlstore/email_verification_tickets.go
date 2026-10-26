package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type verifyTickets struct{ s *Store }

func (s *Store) EmailVerificationTickets() store.EmailVerificationTickets { return verifyTickets{s} }

const verifyTicketCols = `tenant_id, id, token_hash, user_id, connection, client_id, lang, expires_at, used_at, created_at,
 result_url, include_email_in_redirect, email, origin`

func (r verifyTickets) Create(ctx context.Context, t *store.EmailVerificationTicket) error {
	// Retried on deadlock: on MySQL an INSERT can be the victim of a cycle
	// with the range DELETEs of DeleteExpired and DeleteByUser (gap locks).
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO email_verification_tickets (`+verifyTicketCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			t.TenantID, t.ID, t.TokenHash, t.UserID, t.Connection, t.ClientID, t.Lang,
			micros(t.ExpiresAt), nullMicros(t.UsedAt), micros(t.CreatedAt),
			t.ResultURL, t.IncludeEmailInRedirect, t.Email, t.Origin)
		return tx.conflict(err)
	})
}

func (r verifyTickets) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.EmailVerificationTicket, error) {
	t, err := scanVerifyTicket(r.s.queryRow(ctx, `SELECT `+verifyTicketCols+` FROM email_verification_tickets WHERE tenant_id = ? AND token_hash = ?`, tenantID, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

// Consume claims the ticket with one conditional UPDATE by primary key, so
// concurrent callers see exactly one success. The ID is looked up first with
// a plain read: updating through the token_hash index would lock that index
// before the primary key, the reverse of the sweepers' DELETEs, which on
// MySQL can deadlock.
func (r verifyTickets) Consume(ctx context.Context, tenantID, tokenHash string, at time.Time) (*store.EmailVerificationTicket, error) {
	var out *store.EmailVerificationTicket
	var used bool
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out, used = nil, false
		t, err := verifyTickets{tx}.GetByTokenHash(ctx, tenantID, tokenHash)
		if err != nil {
			return err
		}
		if t.UsedAt == nil {
			res, err := tx.exec(ctx, `UPDATE email_verification_tickets SET used_at = ? WHERE tenant_id = ? AND id = ? AND used_at IS NULL`,
				micros(at), tenantID, t.ID)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n == 1 {
				v := fromMicros(micros(at))
				t.UsedAt = &v
				out = t
				return nil
			}
			// Lost the race (or the ticket was deleted). A locking read sees
			// the latest committed row; on MySQL a plain read would reuse the
			// snapshot taken by the lookup above, from before the winner.
			latest, err := verifyTickets{tx}.getLatest(ctx, tenantID, t.ID)
			if err != nil {
				return err
			}
			t = latest
			if t.UsedAt == nil {
				return store.ErrNotFound
			}
		}
		out, used = t, true
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

// getLatest reads a ticket by ID with a row lock; r must be in a transaction.
func (r verifyTickets) getLatest(ctx context.Context, tenantID, id string) (*store.EmailVerificationTicket, error) {
	t, err := scanVerifyTicket(r.s.queryRow(ctx, `SELECT `+verifyTicketCols+` FROM email_verification_tickets WHERE tenant_id = ? AND id = ?`+r.s.d.forUpdate, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (r verifyTickets) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM email_verification_tickets WHERE tenant_id = ? AND user_id = ? AND used_at IS NULL`, tenantID, userID))
		return err
	})
	return n, err
}

func (r verifyTickets) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM email_verification_tickets WHERE expires_at <= ?`, micros(before)))
		return err
	})
	return n, err
}

func scanVerifyTicket(row scanner) (*store.EmailVerificationTicket, error) {
	var t store.EmailVerificationTicket
	var exp, created int64
	var used sql.NullInt64
	if err := row.Scan(&t.TenantID, &t.ID, &t.TokenHash, &t.UserID, &t.Connection, &t.ClientID, &t.Lang,
		&exp, &used, &created, &t.ResultURL, &t.IncludeEmailInRedirect, &t.Email, &t.Origin); err != nil {
		return nil, err
	}
	t.ExpiresAt, t.CreatedAt, t.UsedAt = fromMicros(exp), fromMicros(created), fromNullMicros(used)
	return &t, nil
}
