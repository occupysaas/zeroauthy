package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type refreshTokens struct{ s *Store }

func (s *Store) RefreshTokens() store.RefreshTokens { return refreshTokens{s} }

const refreshCols = `tenant_id, id, token_hash, family_id, client_id, user_id, session_id, scopes, audience,
 auth_time, rotating, expires_at, idle_expires_at, rotated_at, revoked_at, created_at`

// Create retries on deadlock: on MySQL an INSERT can be the victim of a cycle
// with the sweepers' range DELETEs (gap locks).
func (r refreshTokens) Create(ctx context.Context, t *store.RefreshToken) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error { return refreshTokens{tx}.insert(ctx, t) })
}

func (r refreshTokens) insert(ctx context.Context, t *store.RefreshToken) error {
	scopes, err := toJSON(t.Scopes)
	if err != nil {
		return err
	}
	_, err = r.s.exec(ctx, `INSERT INTO refresh_tokens (`+refreshCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.TenantID, t.ID, t.TokenHash, t.FamilyID, t.ClientID, t.UserID, t.SessionID, scopes, t.Audience,
		micros(t.AuthTime), t.Rotating, micros(t.ExpiresAt), micros(t.IdleExpiresAt),
		nullMicros(t.RotatedAt), nullMicros(t.RevokedAt), micros(t.CreatedAt))
	return r.s.conflict(err)
}

func (r refreshTokens) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.RefreshToken, error) {
	t, err := scanRefreshToken(r.s.queryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE tenant_id = ? AND token_hash = ?`, tenantID, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

// Rotate follows the memory driver's order of checks exactly. The old row is
// locked by primary key, so rotations of one token are serialized. A reuse
// commits the family revocation and then reports ErrAlreadyUsed; every other
// error rolls back, so "nothing changes".
func (r refreshTokens) Rotate(ctx context.Context, tenantID, oldID string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	var reused bool
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		reused = false
		old, err := scanRefreshToken(tx.queryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate, tenantID, oldID))
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if old.RevokedAt != nil {
			if old.RotatedAt == nil {
				return store.ErrNotFound
			}
			// A rotated token of a revoked family: reuse, whatever the leeway.
			reused = true
			return nil
		}
		if next.TenantID != tenantID || next.FamilyID != old.FamilyID {
			return store.ErrConflict
		}
		// memory checks a taken successor before reuse; plain point reads
		// take no locks, and a successor inserted concurrently still fails
		// the insert below with ErrConflict.
		var idTaken, hashTaken bool
		if err := tx.queryRow(ctx, `SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE tenant_id = ? AND id = ?),
 EXISTS (SELECT 1 FROM refresh_tokens WHERE tenant_id = ? AND token_hash = ?)`,
			tenantID, next.ID, tenantID, next.TokenHash).Scan(&idTaken, &hashTaken); err != nil {
			return err
		}
		if idTaken || hashTaken {
			return store.ErrConflict
		}
		if old.RotatedAt != nil {
			if leeway <= 0 || !at.Before(old.RotatedAt.Add(leeway)) {
				reused = true
				_, err := revokeUntilStable(ctx, tx, `family_id`, tenantID, old.FamilyID, at)
				return err
			}
		} else if _, err := tx.exec(ctx, `UPDATE refresh_tokens SET rotated_at = ? WHERE tenant_id = ? AND id = ?`, micros(at), tenantID, oldID); err != nil {
			return err
		}
		return refreshTokens{tx}.insert(ctx, next)
	})
	if err != nil {
		return err
	}
	if reused {
		return store.ErrAlreadyUsed
	}
	return nil
}

func (r refreshTokens) Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	res, err := r.s.write(ctx, nil, `UPDATE refresh_tokens SET idle_expires_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL AND rotated_at IS NULL`,
		micros(idleExpiresAt), tenantID, id)
	if err != nil {
		return err
	}
	return expectRow(res)
}

func (r refreshTokens) RevokeFamily(ctx context.Context, tenantID, familyID string, at time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		_, err := revokeUntilStable(ctx, tx, `family_id`, tenantID, familyID, at)
		return err
	})
}

func (r refreshTokens) RevokeByUser(ctx context.Context, tenantID, userID string, at time.Time) (int, error) {
	var n int
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) (err error) {
		n, err = revokeUntilStable(ctx, tx, `user_id`, tenantID, userID, at)
		return err
	})
	return n, err
}

// revokeUntilStable sets revoked_at on every unrevoked token whose column
// (family_id or user_id) equals value, repeating the set-based UPDATE until
// it revokes nothing, and returns how many it revoked. The repeat matters on
// PostgreSQL (READ COMMITTED): an UPDATE that waits on a row being rotated
// re-checks only that row, so it misses the successor the rotation commits;
// the next statement's snapshot sees it. A statement that revokes nothing
// waited on no in-flight rotation, so no successor can still appear. Under
// REPEATABLE READ (MySQL) the loop usually exits after one pass: next-key
// locks make the successor's INSERT wait for the revocation (or deadlock and
// be retried), so there is nothing left to catch.
func revokeUntilStable(ctx context.Context, tx *Store, column, tenantID, value string, at time.Time) (int, error) {
	total := 0
	for {
		n, err := affected(tx.exec(ctx, `UPDATE refresh_tokens SET revoked_at = ? WHERE tenant_id = ? AND `+column+` = ? AND revoked_at IS NULL`,
			micros(at), tenantID, value))
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
		total += n
	}
}

// DeleteExpired runs one range DELETE per expiry index (an OR across both
// columns would scan, and on MySQL lock, the whole table), each in its own
// transaction: on MySQL, keeping the first DELETE's gap locks while the second
// runs deadlocks with a concurrent INSERT.
func (r refreshTokens) DeleteExpired(ctx context.Context, before time.Time) (int, error) {
	total := 0
	for _, col := range []string{`expires_at`, `idle_expires_at`} {
		var n int
		err := r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) (err error) {
			n, err = affected(tx.exec(ctx, `DELETE FROM refresh_tokens WHERE `+col+` > 0 AND `+col+` <= ?`, micros(before)))
			return err
		})
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func scanRefreshToken(row scanner) (*store.RefreshToken, error) {
	var t store.RefreshToken
	var scopes string
	var authAt, exp, idle, created int64
	var rotated, revoked sql.NullInt64
	if err := row.Scan(&t.TenantID, &t.ID, &t.TokenHash, &t.FamilyID, &t.ClientID, &t.UserID, &t.SessionID, &scopes,
		&t.Audience, &authAt, &t.Rotating, &exp, &idle, &rotated, &revoked, &created); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &t.Scopes); err != nil {
		return nil, err
	}
	t.AuthTime, t.ExpiresAt, t.IdleExpiresAt, t.CreatedAt = fromMicros(authAt), fromMicros(exp), fromMicros(idle), fromMicros(created)
	t.RotatedAt, t.RevokedAt = fromNullMicros(rotated), fromNullMicros(revoked)
	return &t, nil
}
