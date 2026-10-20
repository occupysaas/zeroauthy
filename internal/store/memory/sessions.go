package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

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

func (r sessions) Get(_ context.Context, tenantID, id string) (*store.LoginSession, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSession(s), nil
}

func (r sessions) ListByUser(_ context.Context, tenantID, userID string) ([]*store.LoginSession, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.LoginSession
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.UserID == userID {
			out = append(out, cloneSession(s))
		}
	}
	slices.SortFunc(out, func(a, b *store.LoginSession) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.ID, a.ID))
	})
	return out, nil
}

func (r sessions) Touch(_ context.Context, tenantID, id string, at, idleExpiresAt time.Time, ip, userAgent string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	s.IdleExpiresAt = idleExpiresAt
	s.UpdatedAt, s.LastInteractedAt = at, at
	s.LastIP, s.LastUserAgent = ip, userAgent
	return nil
}

func (r sessions) AddClient(_ context.Context, tenantID, id, clientID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	if !slices.Contains(s.ClientIDs, clientID) {
		s.ClientIDs = append(slices.Clone(s.ClientIDs), clientID)
	}
	return nil
}

func (r sessions) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, s := range r.s.sessions {
		if !s.ExpiresAt.After(before) || !s.IdleExpiresAt.After(before) {
			delete(r.s.sessions, k)
			n++
		}
	}
	return n, nil
}

func (r sessions) DeleteByUser(_ context.Context, tenantID, userID string) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.UserID == userID {
			delete(r.s.sessions, k)
			n++
		}
	}
	return n, nil
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
