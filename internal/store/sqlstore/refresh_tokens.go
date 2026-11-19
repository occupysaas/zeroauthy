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
 auth_time, rotating, expires_at, idle_expires_at, rotated_at, revoked_at, created_at, origin, organization_id, organization_connection_id, dpop_jkt, parent_id, access, metadata, device, last_exchanged_at`

// Create retries on deadlock: on MySQL an INSERT can be the victim of a cycle
// with the sweepers' range DELETEs (gap locks).
func (r refreshTokens) Create(ctx context.Context, t *store.RefreshToken) error {
	return r.atomic(ctx, t.TenantID, func(tx *Store) error { return refreshTokens{tx}.insert(ctx, t, t.ParentID) })
}

// A sequence row is the tenant's write lock, including for the very first
// family. Conversions span multiple families and cannot use a single token
// as their lock. Use a current snapshot after acquiring the lock on MySQL.
func (r refreshTokens) atomic(ctx context.Context, tid string, fn func(*Store) error) error {
	return r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		// Tenant, user, client and API deletes take this lock before deleting
		// refresh rows. Join their lock order before assigning an insertion order.
		if err := tx.lockRBAC(ctx, tid); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.insertIgnore(ctx, "refresh_token_sequences (tenant_id,last_order) VALUES (?,0)", tid); err != nil {
			return err
		}
		var seq int64
		if err := tx.queryRow(ctx, "SELECT last_order FROM refresh_token_sequences WHERE tenant_id=?"+tx.d.forUpdate, tid).Scan(&seq); err != nil {
			return err
		}
		return fn(tx)
	})
}
func (r refreshTokens) insert(ctx context.Context, t *store.RefreshToken, parent string) error {
	if _, err := r.s.exec(ctx, "UPDATE refresh_token_sequences SET last_order=last_order+1 WHERE tenant_id=?", t.TenantID); err != nil {
		return err
	}
	access := t.Access
	if access == "" {
		access = "offline"
	}
	scopes, err := toJSON(t.Scopes)
	if err != nil {
		return err
	}
	_, err = r.s.exec(ctx, `INSERT INTO refresh_tokens (`+refreshCols+`, insertion_order) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,(SELECT last_order FROM refresh_token_sequences WHERE tenant_id=?))`,
		t.TenantID, t.ID, t.TokenHash, t.FamilyID, t.ClientID, t.UserID, t.SessionID, scopes, t.Audience,
		micros(t.AuthTime), t.Rotating, micros(t.ExpiresAt), micros(t.IdleExpiresAt),
		nullMicros(t.RotatedAt), nullMicros(t.RevokedAt), micros(t.CreatedAt), t.Origin, t.OrganizationID, t.OrganizationConnectionID, t.DPoPJKT, parent, access, jsonColumn{&t.Metadata}, jsonColumn{&t.Device}, nullMicros(t.LastExchangedAt), t.TenantID)
	return r.s.conflict(err)
}

func (r refreshTokens) GetByTokenHash(ctx context.Context, tenantID, tokenHash string) (*store.RefreshToken, error) {
	t, err := scanRefreshToken(r.s.queryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE tenant_id = ? AND token_hash = ?`, tenantID, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (r refreshTokens) Get(ctx context.Context, tenantID, id string) (*store.RefreshToken, error) {
	t, err := scanRefreshToken(r.s.queryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE tenant_id = ? AND id = ?`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (r refreshTokens) ListByUser(ctx context.Context, tenantID, userID string) ([]*store.RefreshToken, error) {
	rows, err := r.s.query(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE tenant_id = ? AND user_id = ? AND access <> 'online' AND revoked_at IS NULL AND rotated_at IS NULL
 ORDER BY created_at DESC, id`+r.s.d.byteOrder+` DESC`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.RefreshToken
	for rows.Next() {
		t, err := scanRefreshToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke sets revoked_at where it is still NULL, so a second revocation
// keeps the first time; the row is checked to exist either way.
func (r refreshTokens) Revoke(ctx context.Context, tenantID, id string, at time.Time) error {
	return r.atomic(ctx, tenantID, func(tx *Store) error {
		var one int
		err := tx.queryRow(ctx, `SELECT 1 FROM refresh_tokens WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate, tenantID, id).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `UPDATE refresh_tokens SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`, micros(at), tenantID, id)
		return err
	})
}

type refreshTransition uint8

const (
	rotateToken refreshTransition = iota
	convertFromNonRotating
	convertFromRotating
)

func (r refreshTokens) Rotate(ctx context.Context, tid, id string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	return r.transition(ctx, tid, id, next, at, leeway, rotateToken)
}
func (r refreshTokens) ConvertNonRotating(ctx context.Context, tid, id string, next *store.RefreshToken) error {
	if next == nil {
		return store.ErrInvalid
	}
	return r.transition(ctx, tid, id, next, next.CreatedAt, 0, convertFromNonRotating)
}
func (r refreshTokens) ConvertRotating(ctx context.Context, tid, id string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	return r.transition(ctx, tid, id, next, at, leeway, convertFromRotating)
}
func (r refreshTokens) transition(ctx context.Context, tid, id string, next *store.RefreshToken, at time.Time, leeway time.Duration, mode refreshTransition) error {
	convert := mode != rotateToken
	wasRotating := mode == convertFromRotating
	var reused bool
	err := r.atomic(ctx, tid, func(tx *Store) error {
		reused = false
		old, err := scanRefreshToken(tx.queryRow(ctx, "SELECT "+refreshCols+" FROM refresh_tokens WHERE tenant_id=? AND id=?"+tx.d.forUpdate, tid, id))
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if convert && (old.Rotating != wasRotating || old.Access == "online" || (!old.ExpiresAt.IsZero() && !at.Before(old.ExpiresAt)) || (!old.IdleExpiresAt.IsZero() && !at.Before(old.IdleExpiresAt))) {
			return store.ErrNotFound
		}
		if old.RevokedAt != nil {
			if old.RotatedAt == nil {
				return store.ErrNotFound
			}
			return store.ErrAlreadyUsed
		}
		if !old.ValidSuccessor(next) || (!convert && next.FamilyID != old.FamilyID) || (convert && next.Rotating == old.Rotating) {
			return store.ErrConflict
		}
		var taken bool
		if err := tx.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE tenant_id=? AND (id=? OR token_hash=?))", tid, next.ID, next.TokenHash).Scan(&taken); err != nil {
			return err
		}
		if taken {
			return store.ErrConflict
		}
		if convert {
			if next.FamilyID == "" {
				return store.ErrInvalid
			}
			if err := tx.queryRow(ctx, "SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE tenant_id=? AND family_id=?)", tid, next.FamilyID).Scan(&taken); err != nil {
				return err
			}
			if taken {
				return store.ErrConflict
			}
		}
		if old.RotatedAt != nil && mode != convertFromNonRotating {
			allowed, err := (refreshTokens{tx}).canReuse(ctx, old, at, leeway)
			if err != nil {
				return err
			}
			if !allowed {
				reused = true
				_, err := revokeUntilStable(ctx, tx, "family_id", tid, old.FamilyID, at)
				return err
			}
		}
		if convert {
			if err := (refreshTokens{tx}).retireConversionSources(ctx, old, at); err != nil {
				return err
			}
			return (refreshTokens{tx}).insert(ctx, next, "")
		}
		if old.RotatedAt == nil {
			if _, err := tx.exec(ctx, "UPDATE refresh_tokens SET rotated_at=? WHERE tenant_id=? AND id=?", micros(at), tid, id); err != nil {
				return err
			}
		}
		return (refreshTokens{tx}).insert(ctx, next, id)
	})
	if err == nil && reused {
		return store.ErrAlreadyUsed
	}
	return err
}

// canReuse reads the latest live family member while the tenant write lock
// is held. Pre-migration records have no authenticated parent information.
func (r refreshTokens) canReuse(ctx context.Context, old *store.RefreshToken, at time.Time, leeway time.Duration) (bool, error) {
	if leeway <= 0 || !at.Before(old.RotatedAt.Add(leeway)) {
		return false, nil
	}
	var parent string
	err := r.s.queryRow(ctx, `SELECT parent_id FROM refresh_tokens WHERE tenant_id=? AND family_id=? AND revoked_at IS NULL AND rotated_at IS NULL
 AND (expires_at=0 OR expires_at>?) AND (idle_expires_at=0 OR idle_expires_at>?) ORDER BY insertion_order DESC LIMIT 1`+r.s.d.forUpdate, old.TenantID, old.FamilyID, micros(at), micros(at)).Scan(&parent)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && parent == old.ID, err
}

func (r refreshTokens) retireConversionSources(ctx context.Context, old *store.RefreshToken, at time.Time) error {
	const filter = " WHERE tenant_id=? AND client_id=? AND user_id=? AND audience=? AND rotating=? AND access<>'online'"
	args := []any{old.TenantID, old.ClientID, old.UserID, old.Audience, old.Rotating}
	if old.Rotating {
		_, err := r.s.exec(ctx, "UPDATE refresh_tokens SET revoked_at=?"+filter+" AND revoked_at IS NULL", append([]any{micros(at)}, args...)...)
		return err
	}
	_, err := r.s.exec(ctx, "DELETE FROM refresh_tokens"+filter, args...)
	return err
}

func (r refreshTokens) Touch(ctx context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	return r.atomic(ctx, tenantID, func(tx *Store) error {
		res, err := tx.exec(ctx, "UPDATE refresh_tokens SET idle_expires_at=? WHERE tenant_id=? AND id=? AND revoked_at IS NULL AND rotated_at IS NULL", micros(idleExpiresAt), tenantID, id)
		if err != nil {
			return err
		}
		return expectRow(res)
	})
}

func (r refreshTokens) RevokeFamily(ctx context.Context, tenantID, familyID string, at time.Time) error {
	return r.atomic(ctx, tenantID, func(tx *Store) error {
		_, err := revokeUntilStable(ctx, tx, `family_id`, tenantID, familyID, at)
		return err
	})
}

func (r refreshTokens) RevokeByUser(ctx context.Context, tenantID, userID string, at time.Time) (int, error) {
	var n int
	err := r.atomic(ctx, tenantID, func(tx *Store) (err error) {
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
	var rotated, revoked, exchanged sql.NullInt64
	if err := row.Scan(&t.TenantID, &t.ID, &t.TokenHash, &t.FamilyID, &t.ClientID, &t.UserID, &t.SessionID, &scopes,
		&t.Audience, &authAt, &t.Rotating, &exp, &idle, &rotated, &revoked, &created, &t.Origin, &t.OrganizationID, &t.OrganizationConnectionID, &t.DPoPJKT, &t.ParentID, &t.Access, jsonColumn{&t.Metadata}, jsonColumn{&t.Device}, &exchanged); err != nil {
		return nil, err
	}
	if err := fromJSON(scopes, &t.Scopes); err != nil {
		return nil, err
	}
	t.AuthTime, t.ExpiresAt, t.IdleExpiresAt, t.CreatedAt = fromMicros(authAt), fromMicros(exp), fromMicros(idle), fromMicros(created)
	t.LastExchangedAt = fromNullMicros(exchanged)
	t.RotatedAt, t.RevokedAt = fromNullMicros(rotated), fromNullMicros(revoked)
	return &t, nil
}

func (r refreshTokens) revokeWhere(ctx context.Context, tid string, at time.Time, predicate string, args ...any) (int, error) {
	var n int
	err := r.atomic(ctx, tid, func(tx *Store) (err error) {
		n, err = affected(tx.exec(ctx, "UPDATE refresh_tokens SET revoked_at=? WHERE tenant_id=? AND revoked_at IS NULL AND "+predicate, append([]any{micros(at), tid}, args...)...))
		return err
	})
	return n, err
}
func (r refreshTokens) RevokeByUserClient(ctx context.Context, tid, user, client, audience string, at time.Time) (int, error) {
	if audience == "" {
		return r.revokeWhere(ctx, tid, at, "user_id=? AND client_id=?", user, client)
	}
	return r.revokeWhere(ctx, tid, at, "user_id=? AND client_id=? AND audience=?", user, client, audience)
}
func (r refreshTokens) RevokeBySession(ctx context.Context, tid, id string, at time.Time) (int, error) {
	if id == "" {
		return 0, store.ErrInvalid
	}
	return r.revokeWhere(ctx, tid, at, "session_id=?", id)
}
func (r refreshTokens) ListByUserPage(ctx context.Context, tid, user, client, from string, take int) ([]*store.RefreshToken, string, error) {
	if take < 1 || take > 100 {
		return nil, "", store.ErrInvalid
	}
	q := "SELECT " + refreshCols + " FROM refresh_tokens WHERE tenant_id=? AND user_id=? AND id" + r.s.d.byteOrder + ">? AND access<>'online' AND rotated_at IS NULL AND revoked_at IS NULL"
	args := []any{tid, user, from}
	if client != "" {
		q += " AND client_id=?"
		args = append(args, client)
	}
	rows, err := r.s.query(ctx, q+" ORDER BY id"+r.s.d.byteOrder+" LIMIT ?", append(args, take+1)...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	tokens := make([]*store.RefreshToken, 0)
	for rows.Next() {
		t, err := scanRefreshToken(rows)
		if err != nil {
			return nil, "", err
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(tokens) > take {
		return tokens[:take], tokens[take-1].ID, nil
	}
	return tokens, "", nil
}
func (r refreshTokens) UpdateMetadata(ctx context.Context, tid, id string, md map[string]string) (*store.RefreshToken, error) {
	var t *store.RefreshToken
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		res, err := tx.exec(ctx, "UPDATE refresh_tokens SET metadata=? WHERE tenant_id=? AND id=? AND access<>'online'", jsonColumn{&md}, tid, id)
		if err != nil {
			return err
		}
		if err = expectRow(res); err != nil {
			return err
		}
		t, err = (refreshTokens{tx}).Get(ctx, tid, id)
		return err
	})
	return t, err
}
func (r refreshTokens) RecordExchange(ctx context.Context, tid, id, ip, ua string, at time.Time) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var device store.RefreshTokenDevice
		var raw sql.NullString
		err := tx.queryRow(ctx, "SELECT device FROM refresh_tokens WHERE tenant_id=? AND id=? AND revoked_at IS NULL"+tx.d.forUpdate, tid, id).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err = fromJSON(raw.String, &device); err != nil {
			return err
		}
		device.LastIP, device.LastUserAgent = ip, ua
		_, err = tx.exec(ctx, "UPDATE refresh_tokens SET device=?,last_exchanged_at=? WHERE tenant_id=? AND id=?", jsonColumn{&device}, micros(at), tid, id)
		return err
	})
}
