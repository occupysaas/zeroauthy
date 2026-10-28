package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type resetTickets struct{ s *Store }

func (s *Store) PasswordResetTickets() store.PasswordResetTickets { return resetTickets{s} }

const resetTicketCols = `tenant_id, id, token_hash, user_id, connection, client_id, lang, expires_at, used_at, created_at,
 result_url, include_email_in_redirect, mark_email_verified, origin, challenge_passed_at, challenge_result_url`

func (r resetTickets) Create(ctx context.Context, t *store.PasswordResetTicket) error {
	// Retried on deadlock: on MySQL an INSERT can be the victim of a cycle
	// with the range DELETEs of DeleteExpired and DeleteByUser (gap locks).
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO password_reset_tickets (`+resetTicketCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			t.TenantID, t.ID, t.TokenHash, t.UserID, t.Connection, t.ClientID, t.Lang,
			micros(t.ExpiresAt), nullMicros(t.UsedAt), micros(t.CreatedAt),
			t.ResultURL, t.IncludeEmailInRedirect, t.MarkEmailVerified, t.Origin, nullMicros(t.ChallengePassedAt), t.ChallengeResultURL)
		return tx.conflict(err)
	})
}

func (r resetTickets) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.PasswordResetTicket, error) {
	t, err := scanResetTicket(r.s.queryRow(ctx, `SELECT `+resetTicketCols+` FROM password_reset_tickets WHERE tenant_id = ? AND token_hash = ?`, tenantID, tokenHash))
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
func (r resetTickets) Consume(ctx context.Context, tenantID, tokenHash string, at time.Time) (*store.PasswordResetTicket, error) {
	var out *store.PasswordResetTicket
	var used bool
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out, used = nil, false
		t, err := resetTickets{tx}.GetByTokenHash(ctx, tenantID, tokenHash)
		if err != nil {
			return err
		}
		if t.UsedAt == nil {
			res, err := tx.exec(ctx, `UPDATE password_reset_tickets SET used_at = ? WHERE tenant_id = ? AND id = ? AND used_at IS NULL`,
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
			latest, err := resetTickets{tx}.getLatest(ctx, tenantID, t.ID)
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
func (r resetTickets) getLatest(ctx context.Context, tenantID, id string) (*store.PasswordResetTicket, error) {
	t, err := scanResetTicket(r.s.queryRow(ctx, `SELECT `+resetTicketCols+` FROM password_reset_tickets WHERE tenant_id = ? AND id = ?`+r.s.d.forUpdate, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (r resetTickets) DeleteByUser(ctx context.Context, tenantID, userID string) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM password_reset_tickets WHERE tenant_id = ? AND user_id = ? AND used_at IS NULL`, tenantID, userID))
		return err
	})
	return n, err
}

func (r resetTickets) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM password_reset_tickets WHERE expires_at <= ?`, micros(before)))
		return err
	})
	return n, err
}

func scanResetTicket(row scanner) (*store.PasswordResetTicket, error) {
	var t store.PasswordResetTicket
	var exp, created int64
	var used, passed sql.NullInt64
	if err := row.Scan(&t.TenantID, &t.ID, &t.TokenHash, &t.UserID, &t.Connection, &t.ClientID, &t.Lang,
		&exp, &used, &created, &t.ResultURL, &t.IncludeEmailInRedirect, &t.MarkEmailVerified, &t.Origin, &passed, &t.ChallengeResultURL); err != nil {
		return nil, err
	}
	t.ChallengePassedAt = fromNullMicros(passed)
	t.ExpiresAt, t.CreatedAt, t.UsedAt = fromMicros(exp), fromMicros(created), fromNullMicros(used)
	return &t, nil
}

// MarkChallengePassed locks the bearer ticket and refuses spent or expired
// tickets. This write joins a caller's transaction without consuming the ticket.
func (r resetTickets) MarkChallengePassed(ctx context.Context, tenantID, hash string, at time.Time, resultURL string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		ticket, err := (resetTickets{tx}).GetByTokenHash(ctx, tenantID, hash)
		if err != nil {
			return err
		}
		ticket, err = (resetTickets{tx}).getLatest(ctx, tenantID, ticket.ID)
		if err != nil {
			return err
		}
		if ticket.UsedAt != nil {
			return store.ErrAlreadyUsed
		}
		if !ticket.ExpiresAt.After(at) {
			return store.ErrNotFound
		}
		_, err = tx.exec(ctx, `UPDATE password_reset_tickets SET challenge_passed_at=?,challenge_result_url=? WHERE tenant_id=? AND id=?`, micros(at), resultURL, tenantID, ticket.ID)
		return err
	})
}
