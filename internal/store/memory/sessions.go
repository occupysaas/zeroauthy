package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type sessions struct{ s *Store }

func (r sessions) Create(_ context.Context, s *store.LoginSession) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{s.TenantID, s.ID}
	if _, ok := r.s.sessions[k]; ok {
		return store.ErrConflict
	}
	if _, ok := r.findByHash(s.TenantID, s.TokenHash); ok {
		return store.ErrConflict
	}
	r.s.sessions[k] = cloneSession(s)
	return nil
}

func (r sessions) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.LoginSession, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSession(s), nil
}

func (r sessions) Update(_ context.Context, s *store.LoginSession) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{s.TenantID, s.ID}
	if _, ok := r.s.sessions[k]; !ok {
		return store.ErrNotFound
	}
	r.s.sessions[k] = cloneSession(s)
	return nil
}

func (r sessions) Delete(_ context.Context, tenantID, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, id}
	if _, ok := r.s.sessions[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.sessions, k)
	return nil
}

// findByHash is called with the lock held.
func (r sessions) findByHash(tenantID, hash string) (*store.LoginSession, bool) {
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.TokenHash == hash {
			return s, true
		}
	}
	return nil, false
}
