package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// UseSAMLAssertion and PurgeSAMLAssertions implement store.SAMLReplayStore
// (Plan 37a), as the global revocation replay table does.
func (s *Store) UseSAMLAssertion(ctx context.Context, tid, connection, jti string, exp, now time.Time) error {
	if tid == "" || connection == "" || jti == "" || len(jti) > 1024 || !exp.After(now) {
		return store.ErrInvalid
	}
	sum := sha256.Sum256([]byte(jti))
	hash := hex.EncodeToString(sum[:])
	return s.atomicRetry(ctx, nil, func(tx *Store) error {
		var old int64
		err := tx.queryRow(ctx, `SELECT expires_at FROM saml_replay WHERE tenant_id=? AND connection_id=? AND assertion_hash=?`+tx.d.forUpdate, tid, connection, hash).Scan(&old)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.exec(ctx, `INSERT INTO saml_replay (tenant_id,connection_id,assertion_hash,expires_at) VALUES (?,?,?,?)`, tid, connection, hash, micros(exp))
			return tx.conflict(err)
		case err != nil:
			return err
		case old > micros(now):
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `UPDATE saml_replay SET expires_at=? WHERE tenant_id=? AND connection_id=? AND assertion_hash=?`, micros(exp), tid, connection, hash)
		return err
	})
}
func (s *Store) PurgeSAMLAssertions(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	n := 0
	err := s.atomicRetry(ctx, nil, func(tx *Store) error {
		rows, err := tx.query(ctx, `SELECT tenant_id,connection_id,assertion_hash FROM saml_replay WHERE expires_at<=? ORDER BY expires_at LIMIT ?`, micros(before), limit)
		if err != nil {
			return err
		}
		var keys [][3]string
		for rows.Next() {
			var k [3]string
			if err := rows.Scan(&k[0], &k[1], &k[2]); err != nil {
				rows.Close()
				return err
			}
			keys = append(keys, k)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		n = 0
		for _, k := range keys {
			v, err := affected(tx.exec(ctx, `DELETE FROM saml_replay WHERE tenant_id=? AND connection_id=? AND assertion_hash=? AND expires_at<=?`, k[0], k[1], k[2], micros(before)))
			if err != nil {
				return err
			}
			n += v
		}
		return nil
	})
	return n, err
}
