package tenantsetup

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// InitializeCanonical pins identity before any new tenant's audiences are
// created. Existing identity is immutable, including after domain reordering.
func InitializeCanonical(t *store.Tenant, baseDomain string) error {
	expected := ""
	if baseDomain != "" {
		expected = tenant.NormalizeHost(t.Name + "." + tenant.NormalizeHost(baseDomain))
	}
	if t.CanonicalHost != "" {
		if expected != "" && expected != t.CanonicalHost {
			return fmt.Errorf("tenant %q canonical host %q differs from configured %q; explicit identity migration required", t.Name, t.CanonicalHost, expected)
		}
		return nil
	}
	if expected == "" && len(t.Domains) > 0 {
		expected = t.Domains[0]
	}
	// A tenant with no host at all is unreachable and has no Management API;
	// its identity is pinned when an operator first gives it a host.
	if expected == "" {
		return nil
	}
	host, err := hostname.NormalizeOperatorHost(expected)
	if err != nil {
		return fmt.Errorf("tenant %q needs an operator-configured canonical host: %w", t.Name, store.ErrInvalid)
	}
	t.CanonicalHost = host
	return nil
}

// ValidateManagementAPIIdentity refuses unexplained managed audience drift.
// Run before any seed/startup repair that could create an apparently valid API
// alongside the old one and hide existing grants bound to the wrong audience.
func ValidateManagementAPIIdentity(ctx context.Context, st store.Store, t *store.Tenant, baseDomain string) error {
	if t.Reserved {
		return nil
	}
	rows, err := st.ResourceServers().List(ctx, t.ID)
	if err != nil {
		return err
	}
	expected := tenant.ManagementAPIIdentifier(t, baseDomain)
	for _, rs := range rows {
		if rs.IsSystem && rs.Identifier != expected {
			return fmt.Errorf("tenant %q managed Management API audience %q differs from canonical %q; explicit identity migration required", t.Name, rs.Identifier, expected)
		}
	}
	return nil
}

// ReconcileDomains performs the configuration-aware upgrade atomically, before
// listeners, workers or repairs. Old plugins fail capability checks even for an
// empty deployment; bounded read probes do not manufacture tenant IDs or writes.
func ReconcileDomains(ctx context.Context, st store.Store, baseDomain, systemHost, originDomain string) error {
	if _, err := st.CustomDomains().ListDue(ctx, 1); err != nil {
		return fmt.Errorf("custom-domain storage capability: %w", err)
	}
	if _, err := st.TLSAssets().ListExpired(ctx, 1); err != nil {
		return fmt.Errorf("custom-domain TLS storage capability: %w", err)
	}
	return st.WithTx(ctx, func(tx store.Store) error {
		all, err := tx.Tenants().List(ctx)
		if err != nil {
			return err
		}
		systemHost = tenant.NormalizeHost(systemHost)
		for _, t := range all {
			if t.Reserved {
				if t.Name != tenant.SystemName {
					return fmt.Errorf("tenant %q has an unexpected reserved identity", t.Name)
				}
				if t.CanonicalHost != "" && t.CanonicalHost != systemHost {
					return fmt.Errorf("system canonical host %q differs from configured %q; explicit identity migration required", t.CanonicalHost, systemHost)
				}
				if t.CanonicalHost == "" && len(t.Domains) > 0 && tenant.NormalizeHost(t.Domains[0]) != systemHost {
					return fmt.Errorf("system host changed from %q to %q; explicit identity migration required", t.Domains[0], systemHost)
				}
				if systemHost == "" {
					return errors.New("system canonical host is empty")
				}
				t.CanonicalHost = systemHost
			} else {
				if err := InitializeCanonical(t, baseDomain); err != nil {
					return err
				}
				if err := ValidateManagementAPIIdentity(ctx, tx, t, baseDomain); err != nil {
					return err
				}
				for _, d := range append(append([]string{}, t.Domains...), t.CanonicalHost) {
					if h := tenant.NormalizeHost(d); h != "" && (h == systemHost || h == tenant.SystemHost(baseDomain, "")) {
						return fmt.Errorf("tenant %q claims reserved system host %q; repair operator aliases before migration: %w", t.Name, h, store.ErrConflict)
					}
				}
			}
			// API rows may never occupy a reserved deployment namespace, even if a
			// previous writer inserted them before this configuration was enabled.
			domains, err := tx.CustomDomains().List(ctx, t.ID)
			if err != nil {
				return err
			}
			for _, d := range domains {
				for _, suffix := range []string{baseDomain, originDomain} {
					suffix = tenant.NormalizeHost(suffix)
					if suffix != "" && (d.Domain == suffix || strings.HasSuffix(d.Domain, "."+suffix)) {
						return fmt.Errorf("tenant %q API domain %q overlaps reserved namespace %q; repair before migration", t.Name, d.Domain, suffix)
					}
				}
				if d.Domain == systemHost {
					return fmt.Errorf("tenant %q API domain overlaps reserved system host %q", t.Name, systemHost)
				}
			}
			if err := tx.Tenants().Update(ctx, t); err != nil {
				return fmt.Errorf("tenant %q canonical/alias ownership reconciliation: %w", t.Name, err)
			}
		}
		return nil
	})
}
