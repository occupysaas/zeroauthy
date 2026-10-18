package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type operators struct{ s *Store }

func (s *Store) Operators() store.Operators { return operators{s} }

const operatorCols = `tenant_id, user_id, tenants, created_at, updated_at`

func scanOperator(row scanner) (*store.Operator, error) {
	var o store.Operator
	var tenants string
	var created, updated int64
	if err := row.Scan(&o.TenantID, &o.UserID, &tenants, &created, &updated); err != nil {
		return nil, err
	}
	if err := fromJSON(tenants, &o.Tenants); err != nil {
		return nil, err
	}
	o.CreatedAt, o.UpdatedAt = fromMicros(created), fromMicros(updated)
	return &o, nil
}

func (r operators) Get(ctx context.Context, tenantID, userID string) (*store.Operator, error) {
	o, err := scanOperator(r.s.queryRow(ctx, `SELECT `+operatorCols+` FROM operators WHERE tenant_id = ? AND user_id = ?`, tenantID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return o, err
}

// Upsert is SELECT ... FOR UPDATE then UPDATE or INSERT in one transaction.
// A concurrent first insert of the same key loses on the primary key; the
// loser retries once and then finds the row to update.
func (r operators) Upsert(ctx context.Context, o *store.Operator) error {
	tenants, err := toJSON(o.Tenants)
	if err != nil {
		return err
	}
	attempt := func() error {
		return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
			var one int
			err := tx.queryRow(ctx, `SELECT 1 FROM operators WHERE tenant_id = ? AND user_id = ?`+tx.d.forUpdate, o.TenantID, o.UserID).Scan(&one)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				_, err := tx.exec(ctx, `INSERT INTO operators (`+operatorCols+`) VALUES (?,?,?,?,?)`,
					o.TenantID, o.UserID, tenants, micros(o.CreatedAt), micros(o.UpdatedAt))
				return tx.conflict(err)
			case err != nil:
				return err
			}
			_, err = tx.exec(ctx, `UPDATE operators SET tenants = ?, updated_at = ? WHERE tenant_id = ? AND user_id = ?`,
				tenants, micros(o.UpdatedAt), o.TenantID, o.UserID)
			return err
		})
	}
	err = attempt()
	if errors.Is(err, store.ErrConflict) {
		err = attempt()
	}
	return err
}

func (r operators) List(ctx context.Context, tenantID string) ([]*store.Operator, error) {
	rows, err := r.s.query(ctx, `SELECT `+operatorCols+` FROM operators WHERE tenant_id = ? ORDER BY user_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*store.Operator
	for rows.Next() {
		o, err := scanOperator(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (r operators) Delete(ctx context.Context, tenantID, userID string) error {
	res, err := r.s.write(ctx, nil, `DELETE FROM operators WHERE tenant_id = ? AND user_id = ?`, tenantID, userID)
	if err != nil {
		return err
	}
	return expectRow(res)
}
