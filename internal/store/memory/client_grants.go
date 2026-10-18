package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clientGrants struct{ s *Store }

func (r clientGrants) Create(_ context.Context, g *store.ClientGrant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{g.TenantID, g.ID}
	if _, ok := r.s.clientGrants[k]; ok {
		return store.ErrConflict
	}
	if _, ok := r.find(g.TenantID, g.ClientID, g.Audience, g.SubjectType); ok {
		return store.ErrConflict
	}
	r.s.clientGrants[k] = cloneClientGrant(g)
	return nil
}

func (r clientGrants) Find(_ context.Context, tenantID, clientID, audience, subjectType string) (*store.ClientGrant, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	g, ok := r.find(tenantID, clientID, audience, subjectType)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClientGrant(g), nil
}

func (r clientGrants) Update(_ context.Context, g *store.ClientGrant) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{g.TenantID, g.ID}
	old, ok := r.s.clientGrants[k]
	if !ok {
		return store.ErrNotFound
	}
	if old.ClientID != g.ClientID || old.Audience != g.Audience || old.SubjectType != g.SubjectType {
		return store.ErrConflict
	}
	r.s.clientGrants[k] = cloneClientGrant(g)
	return nil
}

func (r clientGrants) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.clientGrants[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.clientGrants, k)
	return nil
}

func (r clientGrants) List(_ context.Context, tenantID string, f store.ClientGrantFilter, p store.Page) ([]*store.ClientGrant, int, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var all []*store.ClientGrant
	for k, g := range r.s.clientGrants {
		if k.tenant == tenantID && (f.ClientID == "" || g.ClientID == f.ClientID) &&
			(f.Audience == "" || g.Audience == f.Audience) && (f.SubjectType == "" || g.SubjectType == f.SubjectType) {
			all = append(all, g)
		}
	}
	slices.SortFunc(all, func(a, b *store.ClientGrant) int { return strings.Compare(a.ID, b.ID) })
	total := len(all)
	all = all[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	out := make([]*store.ClientGrant, len(all))
	for i, g := range all {
		out[i] = cloneClientGrant(g)
	}
	return out, total, nil
}

// find is called with the lock held.
func (r clientGrants) find(tenantID, clientID, audience, subjectType string) (*store.ClientGrant, bool) {
	for k, g := range r.s.clientGrants {
		if k.tenant == tenantID && g.ClientID == clientID && g.Audience == audience && g.SubjectType == subjectType {
			return g, true
		}
	}
	return nil, false
}
