package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type pushedAuthRequests struct{ s *Store }

func (r pushedAuthRequests) Create(_ context.Context, p *store.PushedAuthRequest) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{p.TenantID, p.IDHash}
	if _, ok := r.s.pushedAuthRequests[k]; ok {
		return store.ErrConflict
	}
	r.s.pushedAuthRequests[k] = clonePushedAuthRequest(p)
	return nil
}

func (r pushedAuthRequests) Consume(_ context.Context, tenantID, idHash string, at time.Time) (*store.PushedAuthRequest, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	p, ok := r.s.pushedAuthRequests[key{tenantID, idHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if p.UsedAt != nil {
		return clonePushedAuthRequest(p), store.ErrAlreadyUsed
	}
	t := at
	p.UsedAt = &t
	return clonePushedAuthRequest(p), nil
}

func (r pushedAuthRequests) Get(_ context.Context, tenantID, idHash string) (*store.PushedAuthRequest, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	p, ok := r.s.pushedAuthRequests[key{tenantID, idHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clonePushedAuthRequest(p), nil
}

func (r pushedAuthRequests) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, p := range r.s.pushedAuthRequests {
		if !p.ExpiresAt.After(before) {
			delete(r.s.pushedAuthRequests, k)
			n++
		}
	}
	return n, nil
}
