package memory

import (
	"cmp"
	"context"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type userGrants struct{ s *Store }

// find is called with the lock held.
func (r userGrants) find(tenantID, clientID, userID, audience string) (*store.UserGrant, bool) {
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.ClientID == clientID && g.UserID == userID && g.Audience == audience {
			return g, true
		}
	}
	return nil, false
}

func (r userGrants) Find(_ context.Context, tenantID, clientID, userID, audience string) (*store.UserGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	g, ok := r.find(tenantID, clientID, userID, audience)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUserGrant(g), nil
}

func (r userGrants) Upsert(_ context.Context, g *store.UserGrant) (*store.UserGrant, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if old, ok := r.find(g.TenantID, g.ClientID, g.UserID, g.Audience); ok {
		old.Scopes = slices.Clone(g.Scopes)
		old.UpdatedAt = g.UpdatedAt
		return cloneUserGrant(old), nil
	}
	k := key{g.TenantID, g.ID}
	if _, ok := r.s.userGrants[k]; ok {
		return nil, store.ErrConflict
	}
	r.s.userGrants[k] = cloneUserGrant(g)
	return cloneUserGrant(g), nil
}

func (r userGrants) List(_ context.Context, tenantID string, f store.UserGrantFilter, p store.Page) ([]*store.UserGrant, int, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var all []*store.UserGrant
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && (f.UserID == "" || g.UserID == f.UserID) &&
			(f.ClientID == "" || g.ClientID == f.ClientID) && (f.Audience == "" || g.Audience == f.Audience) {
			all = append(all, g)
		}
	}
	slices.SortFunc(all, func(a, b *store.UserGrant) int { return cmp.Compare(a.ID, b.ID) })
	total := len(all)
	all = all[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	out := make([]*store.UserGrant, len(all))
	for i, g := range all {
		out[i] = cloneUserGrant(g)
	}
	return out, total, nil
}

func (r userGrants) ListByUser(_ context.Context, tenantID, userID string) ([]*store.UserGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.UserGrant
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.UserID == userID {
			out = append(out, cloneUserGrant(g))
		}
	}
	slices.SortFunc(out, func(a, b *store.UserGrant) int {
		return cmp.Or(cmp.Compare(a.ClientID, b.ClientID), cmp.Compare(a.Audience, b.Audience))
	})
	return out, nil
}

func (r userGrants) ListByAudience(_ context.Context, tenantID, audience string) ([]*store.UserGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.UserGrant
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.Audience == audience {
			out = append(out, cloneUserGrant(g))
		}
	}
	slices.SortFunc(out, func(a, b *store.UserGrant) int { return cmp.Compare(a.ID, b.ID) })
	return out, nil
}

func (r userGrants) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.userGrants[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.userGrants, k)
	return nil
}

func (r userGrants) DeleteByUser(_ context.Context, tenantID, userID string) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, g := range r.s.userGrants {
		if k.tenant == tenantID && g.UserID == userID {
			delete(r.s.userGrants, k)
			n++
		}
	}
	return n, nil
}
