package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tenants struct{ s *Store }

func (r tenants) Create(_ context.Context, t *store.Tenant) error {
	if err := store.ValidateProtectionSecrets(t.ProtectionSettings.CAPTCHA); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[t.ID]; ok || r.collides(t) {
		return store.ErrConflict
	}
	r.s.tenants[t.ID] = cloneTenant(t)
	return nil
}

func (r tenants) Get(_ context.Context, id string) (*store.Tenant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.s.tenants[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneTenant(t), nil
}

func (r tenants) GetByName(_ context.Context, name string) (*store.Tenant, error) {
	return r.find(func(t *store.Tenant) bool { return t.Name == name })
}

func (r tenants) GetByDomain(_ context.Context, domain string) (*store.Tenant, error) {
	return r.find(func(t *store.Tenant) bool { return slices.Contains(t.Domains, domain) })
}

func (r tenants) Update(_ context.Context, t *store.Tenant) error {
	if err := store.ValidateProtectionSecrets(t.ProtectionSettings.CAPTCHA); err != nil {
		return err
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[t.ID]; !ok {
		return store.ErrNotFound
	}
	if r.collides(t) {
		return store.ErrConflict
	}
	if p := r.s.protection[t.ID]; p != nil {
		p.Policy(r.s.tenants[t.ID].ProtectionSettings, t.ProtectionSettings)
	}
	r.s.tenants[t.ID] = cloneTenant(t)
	return nil
}

func (r tenants) List(context.Context) ([]*store.Tenant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]*store.Tenant, 0, len(r.s.tenants))
	for _, t := range r.s.tenants {
		out = append(out, cloneTenant(t))
	}
	slices.SortFunc(out, func(a, b *store.Tenant) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Delete removes the tenant and every entity scoped to it.
func (r tenants) Delete(_ context.Context, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[id]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.tenants, id)
	delete(r.s.protection, id)
	s := r.s
	purge(s.clients, id)
	purge(s.resourceServers, id)
	purge(s.clientGrants, id)
	purge(s.userGrants, id)
	purge(s.signingKeys, id)
	delete(s.customSigningKeys, id)
	delete(s.emailProviders, id)
	delete(s.emailProviderRevisions, id)
	purge(s.emailTemplates, id)
	purgeEmailClaims(s.emailNotifications, id)
	purge(s.connections, id)
	purge(s.passwordHistories, id)
	purge(s.users, id)
	purge(s.sessions, id)
	purge(s.transactions, id)
	purge(s.authCodes, id)
	purge(s.pushedAuthRequests, id)
	purge(s.deviceCodes, id)
	purge(s.refreshTokens, id)
	purge(s.resetTickets, id)
	purge(s.verifyTickets, id)
	purge(s.operators, id)
	purge(s.jobs, id)
	purge(s.jobErrors, id)
	purge(s.jobFiles, id)
	return nil
}

// purge deletes the entries of one tenant from m.
func purge[V any](m map[key]V, tenantID string) {
	for k := range m {
		if k.tenant == tenantID {
			delete(m, k)
		}
	}
}

func purgeEmailClaims(m map[emailClaimKey]store.EmailNotification, tenantID string) {
	for k := range m {
		if k.tenant == tenantID {
			delete(m, k)
		}
	}
}

func (r tenants) find(match func(*store.Tenant) bool) (*store.Tenant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, t := range r.s.tenants {
		if match(t) {
			return cloneTenant(t), nil
		}
	}
	return nil, store.ErrNotFound
}

// collides reports whether t's name or domains are used by another tenant,
// or t lists a domain more than once. The caller holds the lock.
func (r tenants) collides(t *store.Tenant) bool {
	seen := make(map[string]bool, len(t.Domains))
	for _, d := range t.Domains {
		if seen[d] {
			return true
		}
		seen[d] = true
	}
	for id, o := range r.s.tenants {
		if id == t.ID {
			continue
		}
		if o.Name == t.Name {
			return true
		}
		for _, d := range t.Domains {
			if slices.Contains(o.Domains, d) {
				return true
			}
		}
	}
	return false
}
