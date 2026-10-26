package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type customDomains struct{ s *Store }

func (s *Store) CustomDomains() store.CustomDomains { return customDomains{s} }

func (s *Store) lockTenant(ctx context.Context, tenant string) error {
	var one int
	err := s.queryRow(ctx, `SELECT 1 FROM tenants WHERE id=?`+s.d.forUpdate, tenant).Scan(&one)
	return missing(err)
}
func missing(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

func (r customDomains) Get(ctx context.Context, tenant, id string) (*store.CustomDomain, error) {
	var payload string
	err := r.s.queryRow(ctx, `SELECT payload FROM custom_domains WHERE tenant_id=? AND id=?`+r.s.txLock(), tenant, id).Scan(&payload)
	if err != nil {
		return nil, missing(err)
	}
	var out store.CustomDomain
	if err = fromJSON(payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
func (s *Store) txLock() string {
	if s.tx != nil {
		return s.d.forUpdate
	}
	return ""
}
func (r customDomains) list(ctx context.Context, q string, args ...any) ([]*store.CustomDomain, error) {
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.CustomDomain{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var d store.CustomDomain
		if err := fromJSON(payload, &d); err != nil {
			return nil, err
		}
		out = append(out, &d)
	}
	return out, rows.Err()
}
func (r customDomains) List(ctx context.Context, tenant string) ([]*store.CustomDomain, error) {
	return r.list(ctx, `SELECT payload FROM custom_domains WHERE tenant_id=? ORDER BY id`, tenant)
}
func (r customDomains) ListDue(ctx context.Context, limit int) ([]*store.CustomDomain, error) {
	if limit < 1 {
		return nil, store.ErrInvalid
	}
	return r.list(ctx, `SELECT payload FROM custom_domains WHERE next_attempt_at<=`+r.s.wallMicros()+` ORDER BY tenant_id,id LIMIT ?`, limit)
}
func (r customDomains) Create(ctx context.Context, d *store.CustomDomain) error {
	if d == nil || d.TenantID == "" || d.ID == "" {
		return store.ErrInvalid
	}
	name, err := hostname.NormalizeDNSName(d.Domain)
	if err != nil {
		return store.ErrInvalid
	}
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockTenant(ctx, d.TenantID); err != nil {
			return err
		}
		if _, err := (customDomains{tx}).Get(ctx, d.TenantID, d.ID); err == nil {
			return store.ErrConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if d.Revision != 0 {
			return store.ErrInvalid
		}
		// Locking reads see current rows even after a caller's earlier List
		// established a MySQL REPEATABLE READ snapshot.
		rows, err := tx.query(ctx, `SELECT id FROM custom_domains WHERE tenant_id=? LIMIT 100`+tx.d.forUpdate, d.TenantID)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if count >= 100 {
			return store.ErrConflict
		}
		c := d.Clone()
		c.Domain = name
		c.Revision = 1
		payload, err := toJSON(c)
		if err != nil {
			return err
		}
		_, err = tx.exec(ctx, `INSERT INTO custom_domains (tenant_id,id,domain,revision,next_attempt_at,payload) VALUES (?,?,?,?,?,?)`, c.TenantID, c.ID, c.Domain, c.Revision, nullMicros(c.NextAttemptAt), payload)
		return tx.conflict(err)
	})
	if err == nil {
		d.Revision = 1
	}
	return err
}
func (r customDomains) Update(ctx context.Context, d *store.CustomDomain, expected int64) error {
	if d == nil || expected < 1 {
		return store.ErrInvalid
	}
	name, err := hostname.NormalizeDNSName(d.Domain)
	if err != nil {
		return store.ErrInvalid
	}
	err = r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockTenant(ctx, d.TenantID); err != nil {
			return err
		}
		old, err := (customDomains{tx}).Get(ctx, d.TenantID, d.ID)
		if err != nil {
			return err
		}
		if old.Revision != expected || old.Domain != name {
			return store.ErrConflict
		}
		c := d.Clone()
		c.Domain = name
		c.Revision = expected + 1
		payload, err := toJSON(c)
		if err != nil {
			return err
		}
		res, err := tx.exec(ctx, `UPDATE custom_domains SET revision=?,next_attempt_at=?,payload=? WHERE tenant_id=? AND id=? AND revision=?`, c.Revision, nullMicros(c.NextAttemptAt), payload, c.TenantID, c.ID, expected)
		if err != nil {
			return err
		}
		return expectRow(res)
	})
	if err == nil {
		d.Revision = expected + 1
	}
	return err
}
func (r customDomains) Delete(ctx context.Context, tenant, id string, expected int64) error {
	if expected < 1 {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockTenant(ctx, tenant); err != nil {
			return err
		}
		old, err := (customDomains{tx}).Get(ctx, tenant, id)
		if err != nil {
			return err
		}
		if old.Revision != expected {
			return store.ErrConflict
		}
		if err := tx.removeDomainState(ctx, tenant, id); err != nil {
			return err
		}
		_, err = tx.exec(ctx, `DELETE FROM custom_domains WHERE tenant_id=? AND id=?`, tenant, id)
		return err
	})
}

// Domain and tenant cascades revoke leases but retain their fencing history.
func (s *Store) removeDomainState(ctx context.Context, tenant, id string) error {
	if err := s.removeTLSAssets(ctx, tenant, id); err != nil {
		return err
	}
	if _, err := s.exec(ctx, `DELETE FROM tenant_domains WHERE tenant_id=? AND domain IN (SELECT host FROM host_bindings WHERE tenant_id=? AND domain_id=?)`, tenant, tenant, id); err != nil {
		return err
	}
	for _, table := range []string{"host_bindings", "custom_domain_attempts", "custom_domain_defaults"} {
		if _, err := s.exec(ctx, `DELETE FROM `+table+` WHERE tenant_id=? AND domain_id=?`, tenant, id); err != nil {
			return err
		}
	}
	return nil
}
func claimName(host, kind string) (string, error) {
	var name string
	var err error
	if kind == store.HostCanonical || kind == store.HostOperator {
		name, err = hostname.NormalizeOperatorHost(host)
	} else {
		name, err = hostname.NormalizeDNSName(host)
	}
	if err != nil {
		return "", store.ErrInvalid
	}
	return name, nil
}
func (r customDomains) GetHost(ctx context.Context, host string) (*store.HostBinding, error) {
	name, err := hostname.NormalizeOperatorHost(host)
	if err != nil {
		return nil, store.ErrInvalid
	}
	var h store.HostBinding
	err = r.s.queryRow(ctx, `SELECT host,tenant_id,domain_id,generation,kind,active FROM host_bindings WHERE host=?`+r.s.txLock(), name).Scan(&h.Host, &h.TenantID, &h.DomainID, &h.Generation, &h.Kind, &h.Active)
	if err != nil {
		return nil, missing(err)
	}
	return &h, nil
}
func (r customDomains) PutHost(ctx context.Context, h *store.HostBinding) error {
	if h == nil || h.TenantID == "" {
		return store.ErrInvalid
	}
	switch h.Kind {
	case store.HostCanonical, store.HostOperator:
		if h.DomainID != "" {
			return store.ErrInvalid
		}
	case store.HostPublic, store.HostOrigin:
		if h.DomainID == "" {
			return store.ErrInvalid
		}
	default:
		return store.ErrInvalid
	}
	name, err := claimName(h.Host, h.Kind)
	if err != nil {
		return err
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockTenant(ctx, h.TenantID); err != nil {
			return err
		}
		old, err := (customDomains{tx}).GetHost(ctx, name)
		if err == nil {
			if old.TenantID != h.TenantID || old.DomainID != h.DomainID || old.Kind != h.Kind {
				return store.ErrConflict
			}
			_, err = tx.exec(ctx, `UPDATE host_bindings SET generation=?,active=? WHERE host=?`, h.Generation, h.Active, name)
			return err
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		_, err = tx.exec(ctx, `INSERT INTO host_bindings (host,tenant_id,domain_id,generation,kind,active) VALUES (?,?,?,?,?,?)`, name, h.TenantID, h.DomainID, h.Generation, h.Kind, h.Active)
		return tx.conflict(err)
	})
}
func (r customDomains) DeleteHost(ctx context.Context, host, tenant, id string) error {
	name, err := hostname.NormalizeOperatorHost(host)
	if err != nil {
		return store.ErrInvalid
	}
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {

		if err := tx.lockTenant(ctx, tenant); err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			// A nonexistent asserted owner still cannot mutate another
			// tenant's existing claim; match the same-owner contract.
			if _, lookupErr := (customDomains{tx}).GetHost(ctx, name); lookupErr != nil {
				return lookupErr
			}
			return store.ErrConflict
		}
		old, err := (customDomains{tx}).GetHost(ctx, name)
		if err != nil {
			return err
		}
		if old.TenantID != tenant || old.DomainID != id || old.Kind == store.HostCanonical {
			return store.ErrConflict
		}
		_, err = tx.exec(ctx, `DELETE FROM host_bindings WHERE host=?`, name)
		return err
	})
}
func (r customDomains) GetDefault(ctx context.Context, tenant string) (string, error) {
	var exists bool
	if err := r.s.queryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id=?)`, tenant).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		return "", store.ErrNotFound
	}
	var id string
	err := r.s.queryRow(ctx, `SELECT domain_id FROM custom_domain_defaults WHERE tenant_id=?`, tenant).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
func (r customDomains) SetDefault(ctx context.Context, tenant, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		if err := tx.lockTenant(ctx, tenant); err != nil {
			return err
		}
		if id != "" {
			if _, err := (customDomains{tx}).Get(ctx, tenant, id); err != nil {
				return err
			}
		}
		if _, err := tx.exec(ctx, `DELETE FROM custom_domain_defaults WHERE tenant_id=?`, tenant); err != nil {
			return err
		}
		if id == "" {
			return nil
		}
		_, err := tx.exec(ctx, `INSERT INTO custom_domain_defaults (tenant_id,domain_id) VALUES (?,?)`, tenant, id)
		return err
	})
}
func (r customDomains) AdmitAttempt(ctx context.Context, tenant, id string) (time.Duration, error) {
	if tenant == "" || id == "" {
		return 0, store.ErrInvalid
	}
	var retry time.Duration
	err := r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		retry = 0
		if err := tx.lockTenant(ctx, tenant); err != nil {
			return err
		}
		now, err := tx.storageNow(ctx)
		if err != nil {
			return err
		}
		var last int64
		err = tx.queryRow(ctx, `SELECT attempted_at FROM custom_domain_attempts WHERE tenant_id=? AND domain_id=?`+tx.d.forUpdate, tenant, id).Scan(&last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && now.Before(fromMicros(last).Add(30*time.Second)) {
			retry = fromMicros(last).Add(30 * time.Second).Sub(now)
		}
		rows, err := tx.query(ctx, `SELECT attempted_at FROM custom_tenant_attempts WHERE tenant_id=? AND attempted_at>? ORDER BY attempted_at,position`+tx.d.forUpdate, tenant, micros(now.Add(-time.Minute)))
		if err != nil {
			return err
		}
		recent := []int64{}
		for rows.Next() {
			var at int64
			if err := rows.Scan(&at); err != nil {
				rows.Close()
				return err
			}
			recent = append(recent, at)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(recent) >= 20 {
			retry = max(retry, fromMicros(recent[0]).Add(time.Minute).Sub(now))
		}
		if retry > 0 {
			return nil
		}
		if _, err := tx.exec(ctx, `DELETE FROM custom_domain_attempts WHERE tenant_id=? AND domain_id=?`, tenant, id); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `INSERT INTO custom_domain_attempts (tenant_id,domain_id,attempted_at) VALUES (?,?,?)`, tenant, id, micros(now)); err != nil {
			return err
		}
		if _, err := tx.exec(ctx, `DELETE FROM custom_tenant_attempts WHERE tenant_id=?`, tenant); err != nil {
			return err
		}
		recent = append(recent, micros(now))
		for i, at := range recent {
			if _, err := tx.exec(ctx, `INSERT INTO custom_tenant_attempts (tenant_id,position,attempted_at) VALUES (?,?,?)`, tenant, i, at); err != nil {
				return err
			}
		}
		return nil
	})
	return retry, err
}
