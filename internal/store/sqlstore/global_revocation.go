package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

func (s *Store) UseGlobalRevocationJTI(ctx context.Context, tid, connection, jti string, exp, now time.Time) error {
	if tid == "" || connection == "" || jti == "" || len(jti) > 256 || !exp.After(now) {
		return store.ErrInvalid
	}
	sum := sha256.Sum256([]byte(jti))
	hash := hex.EncodeToString(sum[:])
	return s.atomicRetry(ctx, nil, func(tx *Store) error {
		var old int64
		err := tx.queryRow(ctx, `SELECT expires_at FROM global_revocation_jtis WHERE tenant_id=? AND connection_id=? AND jti_hash=?`+tx.d.forUpdate, tid, connection, hash).Scan(&old)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.exec(ctx, `INSERT INTO global_revocation_jtis (tenant_id,connection_id,jti_hash,expires_at) VALUES (?,?,?,?)`, tid, connection, hash, micros(exp))
			return tx.conflict(err)
		case err != nil:
			return err
		case old > micros(now):
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `UPDATE global_revocation_jtis SET expires_at=? WHERE tenant_id=? AND connection_id=? AND jti_hash=?`, micros(exp), tid, connection, hash)
		return err
	})
}
func (s *Store) PurgeGlobalRevocationJTIs(ctx context.Context, before time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	n := 0
	err := s.atomicRetry(ctx, nil, func(tx *Store) error {
		rows, err := tx.query(ctx, `SELECT tenant_id,connection_id,jti_hash FROM global_revocation_jtis WHERE expires_at<=? ORDER BY expires_at LIMIT ?`, micros(before), limit)
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
			v, err := affected(tx.exec(ctx, `DELETE FROM global_revocation_jtis WHERE tenant_id=? AND connection_id=? AND jti_hash=? AND expires_at<=?`, k[0], k[1], k[2], micros(before)))
			if err != nil {
				return err
			}
			n += v
		}
		return nil
	})
	return n, err
}
func (s *Store) FindByFederatedEmail(ctx context.Context, tid, connection, email string) (*store.User, error) {
	conn, err := s.Connections().Get(ctx, tid, connection)
	if err != nil {
		return nil, err
	}
	rows, err := s.query(ctx, `SELECT `+userCols+` FROM users WHERE tenant_id=? AND user_id IN (SELECT user_id FROM federated_identities WHERE tenant_id=? AND connection_id=?)`, tid, tid, connection)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found *store.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		if store.FederatedEmailMatches(u, conn.Name, email) {
			if found != nil && found.UserID != u.UserID {
				return nil, store.ErrNotFound
			}
			found = u
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if found == nil {
		return nil, store.ErrNotFound
	}
	return found, nil
}
