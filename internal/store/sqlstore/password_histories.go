package sqlstore

import (
	"bytes"
	"context"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type passwordHistories struct{ s *Store }

func (s *Store) PasswordHistories() store.PasswordHistories { return passwordHistories{s} }

// addAttempts bounds the retries of Add when concurrent adds for one user
// pick the same sequence number.
const addAttempts = 10

func (r passwordHistories) Add(ctx context.Context, tenantID, userID string, hash []byte, keep int) error {
	var err error
	for range addAttempts {
		err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
			if keep <= 0 {
				_, err := tx.exec(ctx, `DELETE FROM password_history WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
				return err
			}
			var last int64
			if err := tx.queryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM password_history WHERE tenant_id = ? AND user_id = ?`,
				tenantID, userID).Scan(&last); err != nil {
				return err
			}
			if _, err := tx.exec(ctx, `INSERT INTO password_history (tenant_id, user_id, seq, hash) VALUES (?,?,?,?)`,
				tenantID, userID, last+1, bytes.Clone(hash)); err != nil {
				return tx.conflict(err)
			}
			_, err := tx.exec(ctx, `DELETE FROM password_history WHERE tenant_id = ? AND user_id = ? AND seq <= ?`,
				tenantID, userID, last+1-int64(keep))
			return err
		})
		// A conflict is another Add for the same user taking the number.
		if !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return err
}

func (r passwordHistories) List(ctx context.Context, tenantID, userID string) ([][]byte, error) {
	rows, err := r.s.query(ctx, `SELECT hash FROM password_history WHERE tenant_id = ? AND user_id = ? ORDER BY seq DESC`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := [][]byte{}
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
