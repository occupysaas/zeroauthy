package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type signingKeys struct{ s *Store }

func (s *Store) SigningKeys() store.SigningKeys { return signingKeys{s} }

const signingKeyCols = `tenant_id, kid, alg, status, private_key, public_jwk, created_at`

func insertSigningKey(ctx context.Context, s *Store, k *store.SigningKey) error {
	_, err := s.exec(ctx, `INSERT INTO signing_keys (`+signingKeyCols+`) VALUES (?,?,?,?,?,?,?)`,
		k.TenantID, k.KID, k.Alg, string(k.Status), nonNilBytes(k.PrivateKey), nonNilBytes(k.PublicJWK), micros(k.CreatedAt))
	return s.conflict(err)
}

// nonNilBytes keeps empty keys as empty BLOBs rather than NULL.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// Create relies on the primary key and the active-key unique index over
// current/next to report ErrConflict.
func (r signingKeys) Create(ctx context.Context, k *store.SigningKey) error {
	return insertSigningKey(ctx, r.s, k)
}

func (r signingKeys) List(ctx context.Context, tenantID string) ([]*store.SigningKey, error) {
	rows, err := r.s.query(ctx, `SELECT `+signingKeyCols+` FROM signing_keys WHERE tenant_id = ? ORDER BY created_at, kid`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.SigningKey
	for rows.Next() {
		var k store.SigningKey
		var status string
		var created int64
		if err := rows.Scan(&k.TenantID, &k.KID, &k.Alg, &status, &k.PrivateKey, &k.PublicJWK, &created); err != nil {
			return nil, err
		}
		k.Status = store.KeyStatus(status)
		k.CreatedAt = fromMicros(created)
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (r signingKeys) Rotate(ctx context.Context, tenantID string, next *store.SigningKey) error {
	if next.Status != store.KeyNext {
		return errors.New("store: the new key must have status next")
	}
	if next.TenantID != tenantID {
		return fmt.Errorf("store: rotate needs a key for tenant %q", tenantID)
	}
	return r.s.atomicRetry(ctx, func(tx *Store) error {
		// Serialize Rotates of a tenant on one deterministic lock, the
		// tenant row, and drain it only to wait. Later statements then see
		// the previous Rotate's committed state (a fresh snapshot on
		// PostgreSQL), and no gap locks are taken on missing rows. A missing
		// tenant row locks nothing, which memory tolerates too.
		rows, err := tx.query(ctx, `SELECT id FROM tenants WHERE id = ?`+tx.d.forUpdate, tenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		var kid string
		dupErr := tx.queryRow(ctx, `SELECT kid FROM signing_keys WHERE tenant_id = ? AND kid = ?`, tenantID, next.KID).Scan(&kid)
		if dupErr == nil {
			return store.ErrConflict
		}
		if !errors.Is(dupErr, sql.ErrNoRows) {
			return dupErr
		}
		err = tx.queryRow(ctx, `SELECT kid FROM signing_keys WHERE tenant_id = ? AND status = ?`,
			tenantID, string(store.KeyNext)).Scan(&kid)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		// Oldest status first, so the active-key unique index is never
		// violated mid-transaction.
		for _, m := range [][2]store.KeyStatus{
			{store.KeyPrevious, store.KeyRevoked},
			{store.KeyCurrent, store.KeyPrevious},
			{store.KeyNext, store.KeyCurrent},
		} {
			if _, err := tx.exec(ctx, `UPDATE signing_keys SET status = ? WHERE tenant_id = ? AND status = ?`,
				string(m[1]), tenantID, string(m[0])); err != nil {
				return err
			}
		}
		return insertSigningKey(ctx, tx, next)
	})
}
