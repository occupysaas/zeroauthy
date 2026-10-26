package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tlsAssets struct{ s *Store }

func (s *Store) TLSAssets() store.TLSAssets { return tlsAssets{s} }

// Each clock query is issued after acquiring the resource lock. PostgreSQL's
// transaction-start timestamp would allow an expired worker to publish.
func (s *Store) wallMicros() string {
	switch s.d.name {
	case "postgres":
		return `CAST(EXTRACT(EPOCH FROM clock_timestamp())*1000000 AS BIGINT)`
	case "mysql":
		return `CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(6))*1000000 AS SIGNED)`
	default:
		return `CAST(unixepoch('subsec')*1000000 AS INTEGER)`
	}
}
func (s *Store) storageNow(ctx context.Context) (time.Time, error) {
	var at int64
	err := s.queryRow(ctx, `SELECT `+s.wallMicros()).Scan(&at)
	return fromMicros(at), err
}
func (r tlsAssets) Get(ctx context.Context, key string) (*store.TLSAsset, error) {
	var payload string
	if err := r.s.queryRow(ctx, `SELECT payload FROM tls_assets WHERE asset_key=?`+r.s.txLock(), key).Scan(&payload); err != nil {
		return nil, missing(err)
	}
	var a store.TLSAsset
	if err := fromJSON(payload, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
func (r tlsAssets) Put(ctx context.Context, a *store.TLSAsset, expected int64) error {
	if a == nil || a.Key == "" || expected < 0 {
		return store.ErrInvalid
	}
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		old, err := (tlsAssets{tx}).Get(ctx, a.Key)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if old == nil && expected != 0 {
			return store.ErrNotFound
		}
		if old != nil && old.Revision != expected {
			return store.ErrConflict
		}
		c := a.Clone()
		c.Revision = expected + 1
		payload, err := toJSON(c)
		if err != nil {
			return err
		}
		if old == nil {
			_, err = tx.exec(ctx, `INSERT INTO tls_assets (asset_key,tenant_id,domain_id,revision,expires_at,payload) VALUES (?,?,?,?,?,?)`, c.Key, c.TenantID, c.DomainID, c.Revision, micros(c.ExpiresAt), payload)
		} else {
			_, err = tx.exec(ctx, `UPDATE tls_assets SET tenant_id=?,domain_id=?,revision=?,expires_at=?,payload=? WHERE asset_key=? AND revision=?`, c.TenantID, c.DomainID, c.Revision, micros(c.ExpiresAt), payload, c.Key, expected)
		}
		return tx.conflict(err)
	})
	if err == nil {
		a.Revision = expected + 1
	}
	return err
}
func (r tlsAssets) Delete(ctx context.Context, key string, expected int64) error {
	if expected < 1 {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		old, err := (tlsAssets{tx}).Get(ctx, key)
		if err != nil {
			return err
		}
		if old.Revision != expected {
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `DELETE FROM tls_assets WHERE asset_key=? AND revision=?`, key, expected)
		return err
	})
}
func (r tlsAssets) ListExpired(ctx context.Context, limit int) ([]*store.TLSAsset, error) {
	if limit < 1 {
		return nil, store.ErrInvalid
	}
	rows, err := r.s.query(ctx, `SELECT payload FROM tls_assets WHERE expires_at>0 AND expires_at<=`+r.s.wallMicros()+` ORDER BY asset_key LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.TLSAsset{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var a store.TLSAsset
		if err := fromJSON(payload, &a); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// insertLeaseHistory leaves a tombstone on release and cascade. Concurrent first
// claims rendezvous on the unique key before locking and incrementing its fence.
func (s *Store) insertLeaseHistory(ctx context.Context, key string) error {
	q := `INSERT INTO tls_leases (resource_key,owner,fence,lease_until) VALUES (?,'',0,0)`
	if s.d.name == "mysql" {
		q += ` ON DUPLICATE KEY UPDATE resource_key=resource_key`
	} else {
		q += ` ON CONFLICT (resource_key) DO NOTHING`
	}
	_, err := s.exec(ctx, q, key)
	return err
}
func (s *Store) lockedLease(ctx context.Context, key string) (*store.TLSLease, error) {
	var l store.TLSLease
	var until int64
	err := s.queryRow(ctx, `SELECT resource_key,owner,fence,lease_until FROM tls_leases WHERE resource_key=?`+s.d.forUpdate, key).Scan(&l.Key, &l.Owner, &l.Fence, &until)
	l.Until = fromMicros(until)
	return &l, err
}
func (s *Store) validLease(ctx context.Context, l store.TLSLease) (*store.TLSLease, error) {
	old, err := s.lockedLease(ctx, l.Key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrConflict
	}
	if err != nil {
		return nil, err
	}
	now, err := s.storageNow(ctx)
	if err != nil {
		return nil, err
	}
	if old.Owner != l.Owner || old.Fence != l.Fence || !now.Before(old.Until) {
		return nil, store.ErrConflict
	}
	return old, nil
}
func (r tlsAssets) ClaimLease(ctx context.Context, key, owner string, duration time.Duration) (*store.TLSLease, error) {
	if key == "" || owner == "" || duration <= 0 {
		return nil, store.ErrInvalid
	}
	var out *store.TLSLease
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.insertLeaseHistory(ctx, key); err != nil {
			return err
		}
		old, err := tx.lockedLease(ctx, key)
		if err != nil {
			return err
		}
		now, err := tx.storageNow(ctx)
		if err != nil {
			return err
		}
		if now.Before(old.Until) {
			return store.ErrConflict
		}
		out = &store.TLSLease{Key: key, Owner: owner, Fence: old.Fence + 1, Until: fromMicros(micros(now.Add(duration)))}
		_, err = tx.exec(ctx, `UPDATE tls_leases SET owner=?,fence=?,lease_until=? WHERE resource_key=?`, out.Owner, out.Fence, micros(out.Until), key)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r tlsAssets) RenewLease(ctx context.Context, l store.TLSLease, duration time.Duration) (*store.TLSLease, error) {
	if duration <= 0 {
		return nil, store.ErrInvalid
	}
	var out *store.TLSLease
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		old, err := tx.validLease(ctx, l)
		if err != nil {
			return err
		}
		now, err := tx.storageNow(ctx)
		if err != nil {
			return err
		}
		old.Until = fromMicros(micros(now.Add(duration)))
		out = old
		_, err = tx.exec(ctx, `UPDATE tls_leases SET lease_until=? WHERE resource_key=?`, micros(old.Until), l.Key)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (r tlsAssets) CheckLease(ctx context.Context, l store.TLSLease) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.validLease(ctx, l); err != nil {
			return err
		}
		if tx.st.checkedLeases == nil {
			tx.st.checkedLeases = map[string]store.TLSLease{}
		}
		tx.st.checkedLeases[l.Key] = l
		return nil
	})
}
func (r tlsAssets) ReleaseLease(ctx context.Context, l store.TLSLease) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if _, err := tx.validLease(ctx, l); err != nil {
			return err
		}
		_, err := tx.exec(ctx, `UPDATE tls_leases SET owner='',lease_until=0 WHERE resource_key=?`, l.Key)
		return err
	})
}
func (s *Store) validateCheckedLeases(ctx context.Context) error {
	for _, key := range sortedLeaseKeys(s.st.checkedLeases) {
		if _, err := s.validLease(ctx, s.st.checkedLeases[key]); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) removeTLSAssets(ctx context.Context, tenant, id string) error {
	q := `SELECT asset_key FROM tls_assets WHERE tenant_id=?`
	args := []any{tenant}
	if id != "" {
		q += ` AND domain_id=?`
		args = append(args, id)
	}
	q += ` ORDER BY asset_key` + s.d.forUpdate
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return err
	}
	keys := []string{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := s.exec(ctx, `UPDATE tls_leases SET owner='',lease_until=0 WHERE resource_key=?`, key); err != nil {
			return err
		}
		if _, err := s.exec(ctx, `DELETE FROM tls_assets WHERE asset_key=?`, key); err != nil {
			return err
		}
	}
	return nil
}
