package memory

import (
	"context"

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

// find is called with the lock held.
func (r clientGrants) find(tenantID, clientID, audience, subjectType string) (*store.ClientGrant, bool) {
	for k, g := range r.s.clientGrants {
		if k.tenant == tenantID && g.ClientID == clientID && g.Audience == audience && g.SubjectType == subjectType {
			return g, true
		}
	}
	return nil, false
}
