package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type deviceCodes struct{ s *Store }

func (s *Store) DeviceCodes() store.DeviceCodes { return deviceCodes{s} }

const deviceCodeCols = `tenant_id, device_code_hash, user_code_hash, client_id, scopes, audience, status, user_id,
 granted_scopes, last_polled_at, expired_reported_at, expires_at, created_at, origin, action_effects`

func (r deviceCodes) Create(ctx context.Context, d *store.DeviceCode) error {
	scopes, err := toJSON(d.Scopes)
	if err != nil {
		return err
	}
	granted, err := toJSON(d.GrantedScopes)
	if err != nil {
		return err
	}
	// Retried on deadlock: on MySQL an INSERT can be the victim of a cycle
	// with DeleteExpired's range DELETE (gap locks).
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		_, err := tx.exec(ctx, `INSERT INTO device_codes (`+deviceCodeCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			d.TenantID, d.DeviceCodeHash, d.UserCodeHash, d.ClientID, scopes, d.Audience, string(d.Status), d.UserID,
			granted, nullMicros(d.LastPolledAt), nullMicros(d.ExpiredReportedAt), micros(d.ExpiresAt), micros(d.CreatedAt), d.Origin, nullBytes(d.ActionEffects))
		return tx.conflict(err)
	})
}

func (r deviceCodes) Get(ctx context.Context, tenantID, deviceCodeHash string) (*store.DeviceCode, error) {
	return r.one(ctx, r.s, ``, `device_code_hash`, tenantID, deviceCodeHash)
}

func (r deviceCodes) GetByUserCode(ctx context.Context, tenantID, userCodeHash string) (*store.DeviceCode, error) {
	return r.one(ctx, r.s, ``, `user_code_hash`, tenantID, userCodeHash)
}

// one reads a code by the given hash column; lock is an optional row-lock suffix.
func (deviceCodes) one(ctx context.Context, s *Store, lock, col, tenantID, hash string) (*store.DeviceCode, error) {
	d, err := scanDeviceCode(s.queryRow(ctx, `SELECT `+deviceCodeCols+` FROM device_codes WHERE tenant_id = ? AND `+col+` = ?`+lock, tenantID, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return d, err
}

// Decide moves a pending code with one conditional UPDATE by primary key, so
// concurrent callers see exactly one success. The read-back runs in the same
// transaction.
func (r deviceCodes) Decide(ctx context.Context, tenantID, deviceCodeHash string, dec store.DeviceDecision) (*store.DeviceCode, error) {
	granted, err := toJSON(dec.GrantedScopes)
	if err != nil {
		return nil, err
	}
	var out *store.DeviceCode
	var decided bool
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out, decided = nil, false
		res, err := tx.exec(ctx, `UPDATE device_codes SET status = ?, user_id = ?, granted_scopes = ?, action_effects = ? WHERE tenant_id = ? AND device_code_hash = ? AND status = 'pending'`,
			string(dec.Status), dec.UserID, granted, nullBytes(dec.ActionEffects), tenantID, deviceCodeHash)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		decided = n > 0
		out, err = deviceCodes{tx}.Get(ctx, tenantID, deviceCodeHash)
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

// Poll applies the rules documented on store.DeviceCodes under a row lock.
func (r deviceCodes) Poll(ctx context.Context, tenantID, deviceCodeHash string, at time.Time) (store.DevicePoll, error) {
	var out store.DevicePoll
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		out = store.DevicePoll{}
		d, err := deviceCodes{}.one(ctx, tx, tx.d.forUpdate, `device_code_hash`, tenantID, deviceCodeHash)
		if err != nil {
			return err
		}
		out.Code = d
		var set string // SET clause applied to the row, if any
		var args []any
		switch {
		case d.Status == store.DeviceCodeConsumed:
			out.Outcome = store.PollInvalid
		case !at.Before(d.ExpiresAt):
			// Expiry is checked before consumption, so an approval the device
			// did not collect before expiry is lost: RFC 8628 treats an expired
			// device code as invalid (Auth0's behaviour here is unobserved).
			if d.ExpiredReportedAt != nil {
				out.Outcome = store.PollInvalid
				break
			}
			out.Outcome = store.PollExpired
			t := at
			d.ExpiredReportedAt = &t
			set, args = `expired_reported_at = ?`, []any{micros(at)}
		case d.LastPolledAt != nil && at.Sub(*d.LastPolledAt) < store.MinPollGap:
			out.Outcome = store.PollSlowDown
		default:
			t := at
			d.LastPolledAt = &t
			set, args = `last_polled_at = ?`, []any{micros(at)}
			switch d.Status {
			case store.DeviceCodeApproved:
				out.Outcome, d.Status = store.PollApproved, store.DeviceCodeConsumed
			case store.DeviceCodeDenied:
				out.Outcome, d.Status = store.PollDenied, store.DeviceCodeConsumed
			default:
				out.Outcome = store.PollPending
			}
			if d.Status == store.DeviceCodeConsumed {
				set += `, status = 'consumed'`
			}
		}
		if set == "" {
			return nil
		}
		_, err = tx.exec(ctx, `UPDATE device_codes SET `+set+` WHERE tenant_id = ? AND device_code_hash = ?`, append(args, tenantID, deviceCodeHash)...)
		return err
	})
	if err != nil {
		return store.DevicePoll{}, err
	}
	return out, nil
}

func (r deviceCodes) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, `DELETE FROM device_codes WHERE expires_at <= ?`, micros(before)))
		return err
	})
	return n, err
}

func scanDeviceCode(row scanner) (*store.DeviceCode, error) {
	var d store.DeviceCode
	var status, scopes, granted string
	var polled, reported sql.NullInt64
	var exp, created int64
	if err := row.Scan(&d.TenantID, &d.DeviceCodeHash, &d.UserCodeHash, &d.ClientID, &scopes, &d.Audience, &status,
		&d.UserID, &granted, &polled, &reported, &exp, &created, &d.Origin, &d.ActionEffects); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &d.Scopes); err != nil {
		return nil, err
	}
	if err := fromJSON(granted, &d.GrantedScopes); err != nil {
		return nil, err
	}
	if len(d.ActionEffects) == 0 {
		d.ActionEffects = nil
	}
	d.Status = store.DeviceCodeStatus(status)
	d.LastPolledAt, d.ExpiredReportedAt = fromNullMicros(polled), fromNullMicros(reported)
	d.ExpiresAt, d.CreatedAt = fromMicros(exp), fromMicros(created)
	return &d, nil
}
