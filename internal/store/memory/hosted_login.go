package memory

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type hostedLogins struct{ s *Store }

func (s *Store) HostedLogins() store.HostedLogins { return hostedLogins{s} }
func (r hostedLogins) Get(_ context.Context, tenantID string) (*store.HostedLoginConfig, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if c := r.s.hostedLogins[tenantID]; c != nil {
		return c.Clone(), nil
	}
	return nil, store.ErrNotFound
}
func (r hostedLogins) Put(_ context.Context, c *store.HostedLoginConfig, expected int64) error {
	if c == nil || c.TenantID == "" || expected < 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[c.TenantID] == nil {
		return store.ErrNotFound
	}
	old := r.s.hostedLogins[c.TenantID]
	if old == nil {
		if expected != 0 {
			return store.ErrConflict
		}
	} else if old.Revision != expected {
		return store.ErrConflict
	}
	copy := c.Clone()
	copy.Revision = expected + 1
	r.s.hostedLogins[c.TenantID] = copy
	return nil
}
