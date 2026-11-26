package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The SQL store implements store.CIBAStore (Plan 41c).

const cibaCols = `tenant_id, id_hash, ticket_hash, origin, client_id, user_id, scopes, audience, binding_message, status, granted_scopes, action_effects, auth_time, mfa_at, poll_interval, last_polled_at, expires_at, created_at`

func scanCIBA(row scanner) (*store.CIBARequest, error) {
	var r store.CIBARequest
	var scopes, granted, status string
	var effects []byte
	var authTime, mfaAt, expires, created int64
	var lastPolled sql.NullInt64
	if err := row.Scan(&r.TenantID, &r.IDHash, &r.TicketHash, &r.Origin, &r.ClientID, &r.UserID, &scopes, &r.Audience, &r.BindingMessage, &status, &granted, &effects,
		&authTime, &mfaAt, &r.Interval, &lastPolled, &expires, &created); err != nil {
		return nil, err
	}
	r.Status = store.CIBAStatus(status)
	if err := fromJSON(scopes, &r.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(granted, &r.GrantedScopes); err != nil {
		return nil, err
	}
	if len(effects) > 0 {
		r.ActionEffects = effects
	}
	if authTime != 0 {
		r.AuthTime = fromMicros(authTime)
	}
	if mfaAt != 0 {
		r.MFAAt = fromMicros(mfaAt)
	}
	if lastPolled.Valid {
		t := fromMicros(lastPolled.Int64)
		r.LastPolledAt = &t
	}
	r.ExpiresAt, r.CreatedAt = fromMicros(expires), fromMicros(created)
	return &r, nil
}

func microsOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return micros(t)
}

func (s *Store) CreateCIBARequest(ctx context.Context, r *store.CIBARequest) error {
	scopes, err := toJSON(r.Scopes)
	if err != nil {
		return err
	}
	granted, err := toJSON(r.GrantedScopes)
	if err != nil {
		return err
	}
	_, err = s.write(ctx, nil, `INSERT INTO ciba_requests (`+cibaCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.TenantID, r.IDHash, r.TicketHash, r.Origin, r.ClientID, r.UserID, scopes, r.Audience, r.BindingMessage, string(r.Status), granted, nullBytes(r.ActionEffects),
		microsOrZero(r.AuthTime), microsOrZero(r.MFAAt), r.Interval, nullMicros(r.LastPolledAt), micros(r.ExpiresAt), micros(r.CreatedAt))
	return s.conflict(err)
}

func (s *Store) cibaOne(ctx context.Context, lock, col, tid, v string) (*store.CIBARequest, error) {
	r, err := scanCIBA(s.queryRow(ctx, `SELECT `+cibaCols+` FROM ciba_requests WHERE tenant_id = ? AND `+col+` = ?`+lock, tid, v))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return r, err
}

func (s *Store) GetCIBARequest(ctx context.Context, tid, idHash string) (*store.CIBARequest, error) {
	return s.cibaOne(ctx, "", "id_hash", tid, idHash)
}

func (s *Store) GetCIBARequestByTicket(ctx context.Context, tid, ticketHash string) (*store.CIBARequest, error) {
	return s.cibaOne(ctx, "", "ticket_hash", tid, ticketHash)
}

// DecideCIBARequest moves a pending request with one conditional UPDATE, so
// concurrent callers see exactly one success.
func (s *Store) DecideCIBARequest(ctx context.Context, tid, idHash string, dec store.CIBADecision) (*store.CIBARequest, error) {
	granted, err := toJSON(dec.GrantedScopes)
	if err != nil {
		return nil, err
	}
	var out *store.CIBARequest
	var decided bool
	err = s.atomicRetry(ctx, nil, func(tx *Store) error {
		out, decided = nil, false
		res, err := tx.exec(ctx, `UPDATE ciba_requests SET status = ?, granted_scopes = ?, action_effects = ?, auth_time = ?, mfa_at = ? WHERE tenant_id = ? AND id_hash = ? AND status = 'pending'`,
			string(dec.Status), granted, nullBytes(dec.ActionEffects), microsOrZero(dec.AuthTime), microsOrZero(dec.MFAAt), tid, idHash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		decided = n == 1
		out, err = tx.cibaOne(ctx, "", "id_hash", tid, idHash)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !decided {
		return out, store.ErrAlreadyUsed
	}
	return out, nil
}

func (s *Store) PollCIBARequest(ctx context.Context, tid, idHash, clientID string, at time.Time) (store.CIBAPoll, *store.CIBARequest, error) {
	var out store.CIBAPoll
	var rec *store.CIBARequest
	err := s.atomicRetry(ctx, nil, func(tx *Store) error {
		r, err := tx.cibaOne(ctx, tx.d.forUpdate, "id_hash", tid, idHash)
		if err != nil {
			return err
		}
		if r.ClientID != clientID {
			return store.ErrNotFound
		}
		before := *r
		out = store.PollCIBA(r, at)
		rec = r
		if r.Status == before.Status && r.Interval == before.Interval && r.LastPolledAt == before.LastPolledAt {
			return nil
		}
		_, err = tx.exec(ctx, `UPDATE ciba_requests SET status = ?, poll_interval = ?, last_polled_at = ? WHERE tenant_id = ? AND id_hash = ?`,
			string(r.Status), r.Interval, nullMicros(r.LastPolledAt), tid, idHash)
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	return out, rec, nil
}

func (s *Store) CountPendingCIBARequests(ctx context.Context, tid string, now time.Time) (int, error) {
	var n int
	err := s.queryRow(ctx, `SELECT COUNT(*) FROM ciba_requests WHERE tenant_id = ? AND status = 'pending' AND expires_at > ?`,
		tid, micros(now.Add(-store.CIBAPendingWindow))).Scan(&n)
	return n, err
}

func (s *Store) DeleteExpiredCIBARequests(ctx context.Context, before time.Time) (int, error) {
	res, err := s.write(ctx, nil, `DELETE FROM ciba_requests WHERE expires_at <= ?`, micros(before))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
