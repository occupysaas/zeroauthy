package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type signingKeys struct{ s *Store }

func (s *Store) SigningKeys() store.SigningKeys { return signingKeys{s} }

const signingKeyCols = `tenant_id, kid, alg, status, private_key, public_jwk, created_at, certificate_der, current_since, current_until, revoked_at`

func insertSigningKey(ctx context.Context, s *Store, k *store.SigningKey) error {
	_, err := s.exec(ctx, `INSERT INTO signing_keys (`+signingKeyCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		k.TenantID, k.KID, k.Alg, string(k.Status), nonNilBytes(k.PrivateKey), nonNilBytes(k.PublicJWK), micros(k.CreatedAt), nullableBytes(k.CertificateDER), nullMicros(k.CurrentSince), nullMicros(k.CurrentUntil), nullMicros(k.RevokedAt))
	return s.conflict(err)
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func (r signingKeys) Create(ctx context.Context, k *store.SigningKey) error {
	if k == nil {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockSigningTenant(ctx, tx, k.TenantID); err != nil {
			return err
		}
		if exists, err := customHasKID(ctx, tx, k.TenantID, k.KID); err != nil {
			return err
		} else if exists {
			return store.ErrConflict
		}
		return insertSigningKey(ctx, tx, k)
	})
}

func (r signingKeys) Get(ctx context.Context, tenantID, kid string) (*store.SigningKey, error) {
	k, err := scanSigningKey(r.s.queryRow(ctx, `SELECT `+signingKeyCols+` FROM signing_keys WHERE tenant_id = ? AND kid = ?`, tenantID, kid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return k, err
}

func (r signingKeys) List(ctx context.Context, tenantID string) ([]*store.SigningKey, error) {
	rows, err := r.s.query(ctx, `SELECT `+signingKeyCols+` FROM signing_keys WHERE tenant_id = ? ORDER BY created_at, kid`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (r signingKeys) Rotate(ctx context.Context, tenantID string, next *store.SigningKey) error {
	if next == nil {
		return store.ErrInvalid
	}
	_, err := r.RotateWithResult(ctx, tenantID, next, next.CreatedAt)
	return err
}

func (r signingKeys) RotateWithResult(ctx context.Context, tenantID string, next *store.SigningKey, at time.Time) (*store.SigningKeyRotation, error) {
	if next == nil || next.Status != store.KeyNext || next.TenantID != tenantID || next.KID == "" {
		return nil, store.ErrInvalid
	}
	var result *store.SigningKeyRotation
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockSigningTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		if exists, err := customHasKID(ctx, tx, tenantID, next.KID); err != nil {
			return err
		} else if exists {
			return store.ErrConflict
		}
		var duplicate string
		dupErr := tx.queryRow(ctx, `SELECT kid FROM signing_keys WHERE tenant_id = ? AND kid = ?`, tenantID, next.KID).Scan(&duplicate)
		if dupErr == nil {
			return store.ErrConflict
		}
		if !errors.Is(dupErr, sql.ErrNoRows) {
			return dupErr
		}
		rows, err := tx.query(ctx, `SELECT `+signingKeyCols+` FROM signing_keys WHERE tenant_id = ?`, tenantID)
		if err != nil {
			return err
		}
		var current, queued *store.SigningKey
		for rows.Next() {
			k, scanErr := scanSigningKey(rows)
			if scanErr != nil {
				rows.Close()
				return scanErr
			}
			if k.Status == store.KeyCurrent {
				current = k
			}
			if k.Status == store.KeyNext {
				queued = k
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if queued == nil {
			return store.ErrNotFound
		}
		if current == nil {
			return store.ErrInvalid
		}
		at = at.UTC()
		if _, err := tx.exec(ctx, `UPDATE signing_keys SET status = ?, current_until = ? WHERE tenant_id = ? AND kid = ?`, string(store.KeyPrevious), micros(at), tenantID, current.KID); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `UPDATE signing_keys SET status = ?, current_since = ?, current_until = NULL, revoked_at = NULL WHERE tenant_id = ? AND kid = ?`, string(store.KeyCurrent), micros(at), tenantID, queued.KID); err != nil {
			return err
		}
		current.Status, current.CurrentUntil = store.KeyPrevious, timePtr(at)
		queued.Status, queued.CurrentSince, queued.CurrentUntil, queued.RevokedAt = store.KeyCurrent, timePtr(at), nil, nil
		newNext := cloneSQLSigningKey(next)
		newNext.CurrentSince, newNext.CurrentUntil, newNext.RevokedAt = nil, nil, nil
		if err := insertSigningKey(ctx, tx, newNext); err != nil {
			return err
		}
		result = &store.SigningKeyRotation{Current: queued, Next: newNext}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r signingKeys) Revoke(ctx context.Context, tenantID, kid string, at time.Time) (*store.SigningKey, error) {
	var result *store.SigningKey
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockSigningTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		k, err := scanSigningKey(tx.queryRow(ctx, `SELECT `+signingKeyCols+` FROM signing_keys WHERE tenant_id = ? AND kid = ?`+tx.d.forUpdate, tenantID, kid))
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if k.Status == store.KeyRevoked {
			result = k
			return nil
		}
		if k.Status != store.KeyPrevious {
			return store.ErrInvalid
		}
		at = at.UTC()
		if _, err := tx.exec(ctx, `UPDATE signing_keys SET status = ?, revoked_at = ? WHERE tenant_id = ? AND kid = ?`, string(store.KeyRevoked), micros(at), tenantID, kid); err != nil {
			return err
		}
		k.Status, k.RevokedAt = store.KeyRevoked, timePtr(at)
		result = k
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r signingKeys) SetCertificateIfAbsent(ctx context.Context, tenantID, kid string, der []byte) (*store.SigningKey, error) {
	var result *store.SigningKey
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockSigningTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		k, err := scanSigningKey(tx.queryRow(ctx, `SELECT `+signingKeyCols+` FROM signing_keys WHERE tenant_id = ? AND kid = ?`+tx.d.forUpdate, tenantID, kid))
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if len(k.CertificateDER) == 0 {
			if _, err := tx.exec(ctx, `UPDATE signing_keys SET certificate_der = ? WHERE tenant_id = ? AND kid = ?`, der, tenantID, kid); err != nil {
				return err
			}
			k.CertificateDER = append([]byte(nil), der...)
		}
		result = k
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func scanSigningKey(row scanner) (*store.SigningKey, error) {
	var k store.SigningKey
	var status string
	var created int64
	var since, until, revoked sql.NullInt64
	if err := row.Scan(&k.TenantID, &k.KID, &k.Alg, &status, &k.PrivateKey, &k.PublicJWK, &created, &k.CertificateDER, &since, &until, &revoked); err != nil {
		return nil, err
	}
	k.Status, k.CreatedAt = store.KeyStatus(status), fromMicros(created)
	k.CurrentSince, k.CurrentUntil, k.RevokedAt = fromNullMicros(since), fromNullMicros(until), fromNullMicros(revoked)
	return &k, nil
}

func lockSigningTenant(ctx context.Context, tx *Store, tenantID string) error {
	rows, err := tx.query(ctx, `SELECT id FROM tenants WHERE id = ?`+tx.d.forUpdate, tenantID)
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	err = rows.Err()
	rows.Close()
	return err
}

func timePtr(t time.Time) *time.Time { v := t; return &v }

func cloneSQLSigningKey(k *store.SigningKey) *store.SigningKey {
	out := *k
	out.PrivateKey = append([]byte(nil), k.PrivateKey...)
	out.PublicJWK = append([]byte(nil), k.PublicJWK...)
	out.CertificateDER = append([]byte(nil), k.CertificateDER...)
	out.CurrentSince = cloneSQLTime(k.CurrentSince)
	out.CurrentUntil = cloneSQLTime(k.CurrentUntil)
	out.RevokedAt = cloneSQLTime(k.RevokedAt)
	return &out
}

func cloneSQLTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}
