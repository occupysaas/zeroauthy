package federation

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// RequireMicrosoftFederation probes the actual backing store on every call.
// A missing capability fails closed; transient errors remain available to callers.
func RequireMicrosoftFederation(ctx context.Context, st store.Store) error {
	supporter, ok := st.(store.MicrosoftFederationSupporter)
	if !ok {
		return store.ErrFederationUnavailable
	}
	return supporter.MicrosoftFederationSupported(ctx)
}

// PreflightMicrosoftIdentities checks every configured Microsoft connection and
// identity without repairing or converting legacy ownership. Run before serving
// traffic, with old writers drained for the rollout.
func PreflightMicrosoftIdentities(ctx context.Context, st store.Store) error {
	tenants, err := st.Tenants().List(ctx)
	if err != nil {
		return err
	}
	microsoft := func(provider string) bool { return provider == rules.WindowsLive || provider == rules.WAAD }
	diagnostic := func(reason string) error {
		return fmt.Errorf("Microsoft federation preflight: %s; operator correction required before startup", reason)
	}
	for _, tenant := range tenants {
		for offset := 0; ; offset += 100 {
			conns, total, err := st.Connections().List(ctx, tenant.ID, store.ConnectionFilter{}, store.Page{Offset: offset, Limit: 100})
			if err != nil {
				return err
			}
			for _, c := range conns {
				if microsoft(c.Strategy) {
					if err := RequireMicrosoftFederation(ctx, st); err != nil {
						return fmt.Errorf("%s: %w", diagnostic("store capability unavailable"), store.ErrFederationUnavailable)
					}
				}
			}
			if len(conns) == 0 || offset+len(conns) >= total {
				break
			}
		}
		for offset := 0; ; offset += 100 {
			users, total, err := st.Users().List(ctx, tenant.ID, nil, store.UserSort{Field: "user_id"}, store.Page{Offset: offset, Limit: 100})
			if err != nil {
				return err
			}
			for _, u := range users {
				filtered := *u
				filtered.Identities = nil
				for _, id := range u.Identities {
					if microsoft(id.Provider) {
						filtered.Identities = append(filtered.Identities, id)
					}
				}
				if len(filtered.Identities) == 0 {
					continue
				}
				if err := RequireMicrosoftFederation(ctx, st); err != nil {
					return fmt.Errorf("%s: %w", diagnostic("store capability unavailable"), store.ErrFederationUnavailable)
				}
				keys, err := store.ResolveFederatedKeys(&filtered, func(name string) (*store.Connection, error) { return st.Connections().GetByName(ctx, tenant.ID, name) })
				if errors.Is(err, store.ErrInvalid) {
					return diagnostic("unresolvable or malformed Microsoft identity")
				}
				if err != nil {
					return err
				}
				for _, key := range keys {
					owner, err := st.Users().FindByIdentity(ctx, key.TenantID, key.ConnectionID, key.Subject)
					if errors.Is(err, store.ErrNotFound) || err == nil && owner.UserID != u.UserID {
						return diagnostic("Microsoft identity index ownership is missing or inconsistent")
					}
					if err != nil {
						return err
					}
				}
			}
			if len(users) == 0 || offset+len(users) >= total {
				break
			}
		}
	}
	return nil
}

// RequireMicrosoftConnection gates only Microsoft's strategies; predecessor
// connections continue working with stores that predate this capability.
func RequireMicrosoftConnection(ctx context.Context, st store.Store, c *store.Connection) error {
	if c != nil && (c.Strategy == rules.WindowsLive || c.Strategy == rules.WAAD) {
		return RequireMicrosoftFederation(ctx, st)
	}
	return nil
}

// RequireMicrosoftUser checks every identity, including linked Microsoft accounts.
func RequireMicrosoftUser(ctx context.Context, st store.Store, u *store.User) error {
	if u != nil {
		for _, id := range u.Identities {
			if id.Provider == rules.WindowsLive || id.Provider == rules.WAAD {
				return RequireMicrosoftFederation(ctx, st)
			}
		}
	}
	return nil
}
