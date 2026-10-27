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
	r.s.lock()
	defer r.s.unlock()
	k := key{rs.TenantID, rs.ID}
	if _, ok := r.s.resourceServers[k]; ok || r.identifierTaken(rs) {
		return store.ErrConflict
	}
	r.s.resourceServers[k] = cloneResourceServer(rs)
	return nil
}

func (r resourceServers) Get(_ context.Context, tenantID, id string) (*store.ResourceServer, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	rs, ok := r.s.resourceServers[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneResourceServer(rs), nil
}

func (r resourceServers) GetByIdentifier(_ context.Context, tenantID, identifier string) (*store.ResourceServer, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, rs := range r.s.resourceServers {
		if k.tenant == tenantID && rs.Identifier == identifier {
			return cloneResourceServer(rs), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r resourceServers) Update(_ context.Context, rs *store.ResourceServer) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{rs.TenantID, rs.ID}
	if _, ok := r.s.resourceServers[k]; !ok {
		return store.ErrNotFound
	}
	if r.identifierTaken(rs) {
		return store.ErrConflict
	}
	r.s.cleanupRBACAPI(rs.TenantID, r.s.resourceServers[k].Identifier, rs.Scopes)
	r.s.resourceServers[k] = cloneResourceServer(rs)
	return nil
}

func (r resourceServers) Delete(_ context.Context, tenantID, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tenantID, id}
	rs, ok := r.s.resourceServers[k]
	if !ok {
		return store.ErrNotFound
	}
	r.s.cleanupRBACAPI(tenantID, rs.Identifier, nil)
	delete(r.s.resourceServers, k)
	// A tenant whose default audience was this API has none now (D-0041).
	if t, ok := r.s.tenants[tenantID]; ok && t.DefaultAudience == rs.Identifier {
		t.DefaultAudience = ""
	}
	for gk, g := range r.s.clientGrants {
		if gk.tenant == tenantID && g.Audience == rs.Identifier {
			delete(r.s.clientGrants, gk)
		}
	}
	for gk, g := range r.s.userGrants {
		if gk.tenant == tenantID && g.Audience == rs.Identifier {
			delete(r.s.userGrants, gk)
		}
	}
	for tk, t := range r.s.refreshTokens {
		if tk.tenant == tenantID && t.Audience == rs.Identifier {
			delete(r.s.refreshTokens, tk)
		}
	}
	return nil
}

func (r resourceServers) List(_ context.Context, tenantID string) ([]*store.ResourceServer, error) {
	r.s.readLock()
	defer r.s.readUnlock()
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

func (r resourceServers) RenameSystem(_ context.Context, tenantID, identifier, name string) error {
	r.s.lock()
	defer r.s.unlock()
	for _, rs := range r.s.resourceServers {
		if rs.TenantID == tenantID && rs.Identifier == identifier && rs.IsSystem {
			rs.Name = name
			return nil
		}
	}
	return store.ErrNotFound
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
