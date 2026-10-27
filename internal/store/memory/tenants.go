package memory

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/hostname"
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
	next, err := r.reconcileHosts(t)
	if err != nil {
		return err
	}
	next.IdentityEpoch = 0 // only Federation moves it
	r.s.tenants[t.ID] = next
	return nil
}

func (r tenants) Get(_ context.Context, id string) (*store.Tenant, error) {
	r.s.readLock()
	defer r.s.readUnlock()
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
	name, err := hostname.NormalizeOperatorHost(domain)
	if err != nil {
		return nil, store.ErrNotFound
	}
	r.s.readLock()
	defer r.s.readUnlock()
	h := r.s.hostBindings[name]
	if h == nil || !h.Active || h.Kind == store.HostOrigin {
		return nil, store.ErrNotFound
	}
	t := r.s.tenants[h.TenantID]
	if t == nil {
		return nil, store.ErrNotFound
	}
	return cloneTenant(t), nil
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
	next, err := r.reconcileHosts(t)
	if err != nil {
		return err
	}
	if p := r.s.protection[t.ID]; p != nil {
		p.Policy(r.s.tenants[t.ID].ProtectionSettings, t.ProtectionSettings)
	}
	next.IdentityEpoch = r.s.tenants[t.ID].IdentityEpoch // only Federation moves it
	r.s.tenants[t.ID] = next
	return nil
}

func (r tenants) List(context.Context) ([]*store.Tenant, error) {
	r.s.readLock()
	defer r.s.readUnlock()
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
	for k := range r.s.customDomains {
		if k.tenant == id {
			r.s.removeDomain(id, k.id)
		}
	}
	for host, h := range r.s.hostBindings {
		if h.TenantID == id {
			delete(r.s.hostBindings, host)
		}
	}
	for key, a := range r.s.tlsAssets {
		if a.TenantID == id {
			delete(r.s.tlsAssets, key)
			r.s.expireLease(key)
		}
	}
	delete(r.s.domainDefaults, id)
	delete(r.s.tenantAttempts, id)
	purge(r.s.domainAttempts, id)
	delete(r.s.tenants, id)
	delete(r.s.protection, id)
	r.s.dropTenantFederation(id)
	s := r.s
	purge(s.clients, id)
	purge(s.resourceServers, id)
	purge(s.clientGrants, id)
	purge(s.userGrants, id)
	purge(s.signingKeys, id)
	delete(s.customSigningKeys, id)
	delete(s.hostedLogins, id)
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
	r.s.readLock()
	defer r.s.readUnlock()
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

// reconcileHosts validates the entire requested projection before mutating any
// claim. Only operator claims are reconciled; API/origin ownership is retained.
// The caller holds the write lock.
func (r tenants) reconcileHosts(t *store.Tenant) (*store.Tenant, error) {
	next := cloneTenant(t)
	seen := map[string]bool{}
	for i, host := range next.Domains {
		name, err := hostname.NormalizeOperatorHost(host)
		if err != nil {
			return nil, store.ErrInvalid
		}
		if seen[name] {
			return nil, store.ErrConflict
		}
		seen[name] = true
		next.Domains[i] = name
	}
	if next.CanonicalHost != "" {
		name, err := hostname.NormalizeOperatorHost(next.CanonicalHost)
		if err != nil {
			return nil, store.ErrInvalid
		}
		next.CanonicalHost = name
	}
	if old := r.s.tenants[t.ID]; old != nil && old.CanonicalHost != "" && old.CanonicalHost != next.CanonicalHost {
		return nil, store.ErrConflict
	}
	if next.CanonicalHost != "" && !seen[next.CanonicalHost] {
		seen[next.CanonicalHost] = true
		next.Domains = append(next.Domains, next.CanonicalHost)
	}
	for host := range seen {
		if h := r.s.hostBindings[host]; h != nil {
			if h.TenantID != t.ID || h.Kind == store.HostOrigin || h.Kind == store.HostPublic && (!h.Active || host == next.CanonicalHost) {
				return nil, store.ErrConflict
			}
		}
	}
	// Preserve active API domains even if an operator omitted them from input.
	active := []string{}
	for host, h := range r.s.hostBindings {
		if h.TenantID == t.ID && h.Kind == store.HostPublic && h.Active && !seen[host] {
			active = append(active, host)
		}
	}
	slices.Sort(active)
	next.Domains = append(next.Domains, active...)
	for host, h := range r.s.hostBindings {
		if h.TenantID == t.ID && h.Kind == store.HostOperator && !seen[host] {
			delete(r.s.hostBindings, host)
		}
	}
	for host := range seen {
		if h := r.s.hostBindings[host]; h != nil && h.DomainID != "" {
			continue
		}
		kind := store.HostOperator
		if host == next.CanonicalHost {
			kind = store.HostCanonical
		}
		r.s.hostBindings[host] = &store.HostBinding{Host: host, TenantID: t.ID, Kind: kind, Active: true}
	}
	return next, nil
}
