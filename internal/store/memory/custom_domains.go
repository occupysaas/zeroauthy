package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type customDomains struct{ s *Store }

func (s *Store) CustomDomains() store.CustomDomains { return customDomains{s} }

func (r customDomains) Get(_ context.Context, tenant, id string) (*store.CustomDomain, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	d := r.s.customDomains[key{tenant, id}]
	if d == nil {
		return nil, store.ErrNotFound
	}
	return d.Clone(), nil
}
func (r customDomains) List(_ context.Context, tenant string) ([]*store.CustomDomain, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := []*store.CustomDomain{}
	for k, d := range r.s.customDomains {
		if k.tenant == tenant {
			out = append(out, d.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *store.CustomDomain) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}
func (r customDomains) ListDue(_ context.Context, limit int) ([]*store.CustomDomain, error) {
	if limit < 1 {
		return nil, store.ErrInvalid
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	now := r.s.now()
	out := []*store.CustomDomain{}
	for _, d := range r.s.customDomains {
		if d.NextAttemptAt != nil && !d.NextAttemptAt.After(now) {
			out = append(out, d.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *store.CustomDomain) int {
		return cmp.Or(cmp.Compare(a.TenantID, b.TenantID), cmp.Compare(a.ID, b.ID))
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (r customDomains) Create(_ context.Context, d *store.CustomDomain) error {
	if d == nil || d.TenantID == "" || d.ID == "" {
		return store.ErrInvalid
	}
	name, err := hostname.NormalizeDNSName(d.Domain)
	if err != nil {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{d.TenantID, d.ID}
	if r.s.customDomains[k] != nil {
		return store.ErrConflict
	}
	if d.Revision != 0 {
		return store.ErrInvalid
	}
	if r.s.tenants[d.TenantID] == nil {
		return store.ErrNotFound
	}
	c := d.Clone()
	c.Domain = name
	c.Revision = 1
	r.s.customDomains[k] = c
	d.Revision = 1
	return nil
}
func (r customDomains) Update(_ context.Context, d *store.CustomDomain, expected int64) error {
	if d == nil || expected < 1 {
		return store.ErrInvalid
	}
	name, err := hostname.NormalizeDNSName(d.Domain)
	if err != nil {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{d.TenantID, d.ID}
	old := r.s.customDomains[k]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Revision != expected {
		return store.ErrConflict
	}
	// Host renames require a new domain record; lifecycle generation is CAS state.
	if name != old.Domain {
		return store.ErrConflict
	}
	c := d.Clone()
	c.Domain = name
	c.Revision = expected + 1
	r.s.customDomains[k] = c
	d.Revision = c.Revision
	return nil
}
func (r customDomains) Delete(_ context.Context, tenant, id string, expected int64) error {
	if expected < 1 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	k := key{tenant, id}
	old := r.s.customDomains[k]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Revision != expected {
		return store.ErrConflict
	}
	r.s.removeDomain(tenant, id)
	return nil
}

// removeDomain is called with the write lock. Deployment assets have no tenant
// or domain ownership and are never matched by this cascade.
func (s *Store) removeDomain(tenant, id string) {
	delete(s.customDomains, key{tenant, id})
	delete(s.domainAttempts, key{tenant, id})
	for host, h := range s.hostBindings {
		if h.TenantID == tenant && h.DomainID == id {
			delete(s.hostBindings, host)
		}
	}
	for k, a := range s.tlsAssets {
		if a.TenantID == tenant && a.DomainID == id {
			delete(s.tlsAssets, k)
			s.expireLease(k)
		}
	}
	if s.domainDefaults[tenant] == id {
		delete(s.domainDefaults, tenant)
	}
	if t := s.tenants[tenant]; t != nil {
		t.Domains = slices.DeleteFunc(t.Domains, func(host string) bool { h := s.hostBindings[host]; return h == nil })
	}
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
func (r customDomains) GetHost(_ context.Context, host string) (*store.HostBinding, error) {
	name, err := hostname.NormalizeOperatorHost(host)
	if err != nil {
		return nil, store.ErrInvalid
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	h := r.s.hostBindings[name]
	if h == nil {
		return nil, store.ErrNotFound
	}
	c := *h
	return &c, nil
}
func (r customDomains) PutHost(_ context.Context, h *store.HostBinding) error {
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
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[h.TenantID] == nil {
		return store.ErrNotFound
	}
	if old := r.s.hostBindings[name]; old != nil && (old.TenantID != h.TenantID || old.DomainID != h.DomainID || old.Kind != h.Kind) {
		return store.ErrConflict
	}
	c := *h
	c.Host = name
	r.s.hostBindings[name] = &c
	return nil
}
func (r customDomains) DeleteHost(_ context.Context, host, tenant, id string) error {
	name, err := hostname.NormalizeOperatorHost(host)
	if err != nil {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.hostBindings[name]
	if old == nil {
		return store.ErrNotFound
	}
	if old.TenantID != tenant || old.DomainID != id || old.Kind == store.HostCanonical {
		return store.ErrConflict
	}
	delete(r.s.hostBindings, name)
	return nil
}
func (r customDomains) GetDefault(_ context.Context, tenant string) (string, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	if r.s.tenants[tenant] == nil {
		return "", store.ErrNotFound
	}
	return r.s.domainDefaults[tenant], nil
}
func (r customDomains) SetDefault(_ context.Context, tenant, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[tenant] == nil {
		return store.ErrNotFound
	}
	if id != "" && r.s.customDomains[key{tenant, id}] == nil {
		return store.ErrNotFound
	}
	r.s.domainDefaults[tenant] = id
	return nil
}
func (r customDomains) AdmitAttempt(_ context.Context, tenant, id string) (time.Duration, error) {
	if tenant == "" || id == "" {
		return 0, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[tenant] == nil {
		return 0, store.ErrNotFound
	}
	now := r.s.now()
	k := key{tenant, id}
	var retry time.Duration
	if last, ok := r.s.domainAttempts[k]; ok && now.Before(last.Add(30*time.Second)) {
		retry = last.Add(30 * time.Second).Sub(now)
	}
	recent := []time.Time{}
	for _, at := range r.s.tenantAttempts[tenant] {
		if now.Before(at.Add(time.Minute)) {
			recent = append(recent, at)
		}
	}
	if len(recent) >= 20 {
		retry = max(retry, recent[0].Add(time.Minute).Sub(now))
	}
	if retry > 0 {
		return retry, nil
	}
	r.s.domainAttempts[k] = now
	r.s.tenantAttempts[tenant] = append(recent, now)
	return 0, nil
}
