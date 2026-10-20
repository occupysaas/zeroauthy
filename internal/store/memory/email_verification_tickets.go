package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type verifyTickets struct{ s *Store }

// findByHash is called with the lock held.
func (r verifyTickets) findByHash(tenantID, hash string) (*store.EmailVerificationTicket, bool) {
	for k, t := range r.s.verifyTickets {
		if k.tenant == tenantID && t.TokenHash == hash {
			return t, true
		}
	}
	return nil, false
}

func (r verifyTickets) Create(_ context.Context, t *store.EmailVerificationTicket) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.verifyTickets[key{t.TenantID, t.ID}]; ok {
		return store.ErrConflict
	}
	if _, ok := r.findByHash(t.TenantID, t.TokenHash); ok {
		return store.ErrConflict
	}
	r.s.verifyTickets[key{t.TenantID, t.ID}] = cloneVerifyTicket(t)
	return nil
}

func (r verifyTickets) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.EmailVerificationTicket, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneVerifyTicket(t), nil
}

func (r verifyTickets) Consume(_ context.Context, tenantID, tokenHash string, at time.Time) (*store.EmailVerificationTicket, error) {
	r.s.lock()
	defer r.s.unlock()
	t, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	if t.UsedAt != nil {
		return cloneVerifyTicket(t), store.ErrAlreadyUsed
	}
	v := at
	t.UsedAt = &v
	return cloneVerifyTicket(t), nil
}

func (r verifyTickets) DeleteByUser(_ context.Context, tenantID, userID string) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, t := range r.s.verifyTickets {
		if k.tenant == tenantID && t.UserID == userID && t.UsedAt == nil {
			delete(r.s.verifyTickets, k)
			n++
		}
	}
	return n, nil
}

func (r verifyTickets) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, t := range r.s.verifyTickets {
		if !t.ExpiresAt.After(before) {
			delete(r.s.verifyTickets, k)
			n++
		}
	}
	return n, nil
}
