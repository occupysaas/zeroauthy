package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type hostedLogins struct{ s *Store }

func (s *Store) HostedLogins() store.HostedLogins { return hostedLogins{s} }
func (r hostedLogins) Get(ctx context.Context, tenantID string) (*store.HostedLoginConfig, error) {
	var rev int64
	var raw string
	err := r.s.queryRow(ctx, `SELECT revision,config FROM hosted_login_configs WHERE tenant_id=?`, tenantID).Scan(&rev, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c store.HostedLoginConfig
	if err = fromJSON(raw, &c); err != nil {
		return nil, err
	}
	c.Revision = rev
	return &c, nil
}
func (r hostedLogins) Put(ctx context.Context, c *store.HostedLoginConfig, expected int64) error {
	if c == nil || c.TenantID == "" || expected < 0 {
		return store.ErrInvalid
	}
	copy := c.Clone()
	copy.Revision = expected + 1
	raw, err := toJSON(copy)
	if err != nil {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := lockEmailTenant(ctx, tx, c.TenantID); err != nil {
			return err
		}
		if expected == 0 {
			_, err = tx.exec(ctx, `INSERT INTO hosted_login_configs(tenant_id,revision,config) VALUES(?,?,?)`, c.TenantID, 1, raw)
			return tx.conflict(err)
		}
		res, err := tx.exec(ctx, `UPDATE hosted_login_configs SET revision=?,config=? WHERE tenant_id=? AND revision=?`, expected+1, raw, c.TenantID, expected)
		if err != nil {
			return tx.conflict(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return store.ErrConflict
		}
		return nil
	})
}
