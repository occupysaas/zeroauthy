package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The caller holds the tenant lock. Registry uniqueness arbitrates competing
// tenants; only this tenant's operator claims may be reconciled here.
func (r tenants) reconcileHosts(ctx context.Context, t, old *store.Tenant) (*store.Tenant, error) {
	next := *t
	next.Domains = slices.Clone(t.Domains)
	// Existing raw legacy aliases may differ in case/terminal dot yet share
	// one operator claim. Preserve unchanged projections for metadata/canonical
	// initialization; explicit replacement input remains strictly normalized.
	preserveRaw := old != nil && slices.Equal(t.Domains, old.Domains)
	seen := map[string]bool{}
	for i, host := range next.Domains {
		name, err := hostname.NormalizeOperatorHost(host)
		if err != nil {
			return nil, store.ErrInvalid
		}
		if seen[name] {
			if !preserveRaw {
				return nil, store.ErrConflict
			}
			h, err := (customDomains{r.s}).GetHost(ctx, name)
			if err != nil {
				return nil, err
			}
			if h.TenantID != t.ID || (h.Kind != store.HostOperator && h.Kind != store.HostCanonical) {
				return nil, store.ErrConflict
			}
		}
		seen[name] = true
		if !preserveRaw {
			next.Domains[i] = name
		}
	}
	if next.CanonicalHost != "" {
		name, err := hostname.NormalizeOperatorHost(next.CanonicalHost)
		if err != nil {
			return nil, store.ErrInvalid
		}
		next.CanonicalHost = name
	}
	if old != nil && old.CanonicalHost != "" && old.CanonicalHost != next.CanonicalHost {
		return nil, store.ErrConflict
	}
	if next.CanonicalHost != "" && !seen[next.CanonicalHost] {
		seen[next.CanonicalHost] = true
		next.Domains = append(next.Domains, next.CanonicalHost)
	}
	// Lock in host order, including absent hosts, to minimize cross-tenant cycles.
	for _, host := range slices.Sorted(maps.Keys(seen)) {
		h, err := (customDomains{r.s}).GetHost(ctx, host)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if h != nil {
			if h.TenantID != t.ID || h.Kind == store.HostOrigin || h.Kind == store.HostPublic && (!h.Active || host == next.CanonicalHost) {
				return nil, store.ErrConflict
			}
			if h.DomainID != "" {
				continue
			}
			kind := store.HostOperator
			if host == next.CanonicalHost {
				kind = store.HostCanonical
			}
			if _, err := r.s.exec(ctx, `UPDATE host_bindings SET kind=?,active=true WHERE host=?`, kind, host); err != nil {
				return nil, err
			}
		} else {
			kind := store.HostOperator
			if host == next.CanonicalHost {
				kind = store.HostCanonical
			}
			if _, err := r.s.exec(ctx, `INSERT INTO host_bindings (host,tenant_id,domain_id,generation,kind,active) VALUES (?,?,'',0,?,true)`, host, t.ID, kind); err != nil {
				return nil, r.s.conflict(err)
			}
		}
	}
	rows, err := r.s.query(ctx, `SELECT host,kind,active FROM host_bindings WHERE tenant_id=? ORDER BY host`+r.s.d.forUpdate, t.ID)
	if err != nil {
		return nil, err
	}
	remove := []string{}
	for rows.Next() {
		var host, kind string
		var active bool
		if err := rows.Scan(&host, &kind, &active); err != nil {
			rows.Close()
			return nil, err
		}
		if !seen[host] {
			if kind == store.HostOperator {
				remove = append(remove, host)
			} else if kind == store.HostPublic && active {
				next.Domains = append(next.Domains, host)
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, host := range remove {
		if _, err := r.s.exec(ctx, `DELETE FROM host_bindings WHERE host=?`, host); err != nil {
			return nil, err
		}
	}
	return &next, nil
}

// Migration keeps tenant_domains bytes/order intact, while installing normalized
// operator claims. Configuration-dependent canonical identity is initialized by
// startup later, before requests are served.
func (s *Store) migrateLegacyHostClaims(ctx context.Context) error {
	rows, err := s.query(ctx, `SELECT domain,tenant_id FROM tenant_domains ORDER BY domain`)
	if err != nil {
		return err
	}
	type claim struct{ host, tenant string }
	claims := []claim{}
	for rows.Next() {
		var c claim
		if err := rows.Scan(&c.host, &c.tenant); err != nil {
			rows.Close()
			return err
		}
		claims = append(claims, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range claims {
		name, err := hostname.NormalizeOperatorHost(c.host)
		if err != nil {
			return fmt.Errorf("legacy hostname %q for tenant %q is invalid; repair tenant domains before migrating: %w", c.host, c.tenant, err)
		}
		old, err := (customDomains{s}).GetHost(ctx, name)
		if err == nil {
			if old.TenantID == c.tenant && old.Kind == store.HostOperator && old.DomainID == "" {
				continue
			}
			return fmt.Errorf("normalized legacy hostname %q overlaps tenants %q and %q; repair tenant domains before migrating", name, old.TenantID, c.tenant)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if _, err := s.exec(ctx, `INSERT INTO host_bindings (host,tenant_id,domain_id,generation,kind,active) VALUES (?,?,'',0,?,true)`, name, c.tenant, store.HostOperator); err != nil {
			return err
		}
	}
	return nil
}
