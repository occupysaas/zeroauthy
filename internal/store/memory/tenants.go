package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tenants struct{ s *Store }

func (r tenants) Create(_ context.Context, t *store.Tenant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
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
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.tenants[t.ID]; !ok {
		return store.ErrNotFound
	}
	if r.collides(t) {
		return store.ErrConflict
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

// collides reports whether t's name or domains are used by another tenant.
// The caller holds the lock.
func (r tenants) collides(t *store.Tenant) bool {
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
