package memory

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type resourceServers struct{ s *Store }

func (r resourceServers) Create(_ context.Context, rs *store.ResourceServer) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{rs.TenantID, rs.ID}
	if _, ok := r.s.resourceServers[k]; ok || r.identifierTaken(rs) {
		return store.ErrConflict
	}
	r.s.resourceServers[k] = cloneResourceServer(rs)
	return nil
}

func (r resourceServers) Get(_ context.Context, tenantID, id string) (*store.ResourceServer, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	rs, ok := r.s.resourceServers[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneResourceServer(rs), nil
}

func (r resourceServers) GetByIdentifier(_ context.Context, tenantID, identifier string) (*store.ResourceServer, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for k, rs := range r.s.resourceServers {
		if k.tenant == tenantID && rs.Identifier == identifier {
			return cloneResourceServer(rs), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r resourceServers) Update(_ context.Context, rs *store.ResourceServer) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{rs.TenantID, rs.ID}
	if _, ok := r.s.resourceServers[k]; !ok {
		return store.ErrNotFound
	}
	if r.identifierTaken(rs) {
		return store.ErrConflict
	}
	r.s.resourceServers[k] = cloneResourceServer(rs)
	return nil
}

func (r resourceServers) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.resourceServers[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.resourceServers, k)
	return nil
}

func (r resourceServers) List(_ context.Context, tenantID string) ([]*store.ResourceServer, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.ResourceServer
	for k, rs := range r.s.resourceServers {
		if k.tenant == tenantID {
			out = append(out, cloneResourceServer(rs))
		}
	}
	slices.SortFunc(out, func(a, b *store.ResourceServer) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	return out, nil
}

// identifierTaken reports whether another resource server in the tenant
// uses rs.Identifier. The caller holds the lock.
func (r resourceServers) identifierTaken(rs *store.ResourceServer) bool {
	for k, o := range r.s.resourceServers {
		if k.tenant == rs.TenantID && k.id != rs.ID && o.Identifier == rs.Identifier {
			return true
		}
	}
	return false
}
