package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type dpopProofs struct{ s *Store }

func (s *Store) DPoP() store.DPoP { return dpopProofs{s} }
func (r dpopProofs) UseProof(ctx context.Context, tid, origin, jkt, jti string, now, expires time.Time) error {
	if tid == "" || origin == "" || jkt == "" || jti == "" || !now.Before(expires) {
		return store.ErrInvalid
	}
	hash := sha256.Sum256([]byte(jti))
	key := []any{tid, origin, jkt, hex.EncodeToString(hash[:])}
	return r.s.atomicRetry(ctx, r.s.sweep(), func(tx *Store) error {
		// Insert an immediately claimable row if absent. The conditional UPDATE
		// serializes both first claim and expired claim replacement.
		if err := tx.insertIgnore(ctx, "dpop_proofs (tenant_id,origin,jkt,jti_hash,expires_at) VALUES (?,?,?,?,?)", append(key, micros(now))...); err != nil {
			return err
		}
		args := append([]any{micros(expires)}, key...)
		n, err := affected(tx.exec(ctx, "UPDATE dpop_proofs SET expires_at=? WHERE tenant_id=? AND origin=? AND jkt=? AND jti_hash=? AND expires_at<=?", append(args, micros(now))...))
		if err == nil && n == 0 {
			return store.ErrConflict
		}
		return err
	})
}

func (r dpopProofs) PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error) {
	return r.s.purgeExpiredKeys(ctx, "dpop_proofs", "tenant_id,origin,jkt,jti_hash", "expires_at", before, limit)
}

// The indexed ordered subquery bounds a batch even when most rows are live.
// The outer deadline predicate protects claims replaced while a DELETE waits.
func (s *Store) purgeExpiredKeys(ctx context.Context, table, keys, expiry string, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	filter := expiry + "<=?"
	ordered := " WHERE " + filter + " ORDER BY " + expiry + " LIMIT ?"
	if s.d.name == "mysql" {
		return affected(s.write(ctx, s.sweep(), "DELETE FROM "+table+ordered, micros(before), limit))
	}
	return affected(s.write(ctx, s.sweep(), "DELETE FROM "+table+" WHERE "+filter+" AND ("+keys+") IN (SELECT "+keys+" FROM "+table+ordered+")", micros(before), micros(before), limit))
}
