package customdomain

import (
	"context"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ReconcileOperatorAliases replaces privileged aliases only. Storage retains
// public claims and their active projection, and arbitrates global ownership in
// this same transaction. Public API domain handlers must never call this path.
func ReconcileOperatorAliases(ctx context.Context, st store.Store, tenantID string, aliases []string) error {
	return st.WithTx(ctx, func(tx store.Store) error {
		t, err := tx.Tenants().Get(ctx, tenantID)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(aliases))
		seen := map[string]bool{}
		for _, raw := range aliases {
			host, err := hostname.NormalizeOperatorHost(raw)
			if err != nil {
				return fmt.Errorf("operator alias %q: %w", raw, store.ErrInvalid)
			}
			if seen[host] {
				return fmt.Errorf("duplicate operator alias %q: %w", host, store.ErrConflict)
			}
			seen[host] = true
			names = append(names, host)
		}
		if t.CanonicalHost != "" && !slices.Contains(names, t.CanonicalHost) {
			return fmt.Errorf("cannot remove canonical host %q; an explicit identity migration is required: %w", t.CanonicalHost, store.ErrConflict)
		}
		t.Domains = names
		return tx.Tenants().Update(ctx, t)
	})
}

// ResolveHost reads only active browser-facing claims. An origin alias or a
// pending customer name must never become a tenant route through this helper.
func ResolveHost(ctx context.Context, st store.Store, host string) (*store.HostBinding, error) {
	name, err := hostname.NormalizeOperatorHost(host)
	if err != nil {
		return nil, store.ErrNotFound
	}
	h, err := st.CustomDomains().GetHost(ctx, name)
	if err != nil {
		return nil, err
	}
	if !h.Active || h.Kind == store.HostOrigin {
		return nil, store.ErrNotFound
	}
	return h, nil
}
