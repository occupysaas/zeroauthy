package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type resetTickets struct{ s *Store }

// findByHash is called with the lock held.
func (r resetTickets) findByHash(tenantID, hash string) (*store.PasswordResetTicket, bool) {
	for k, t := range r.s.resetTickets {
		if k.tenant == tenantID && t.TokenHash == hash {
			return t, true
		}
	}
	return nil, false
}

func (r resetTickets) Create(_ context.Context, t *store.PasswordResetTicket) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.resetTickets[key{t.TenantID, t.ID}]; ok {
		return store.ErrConflict
	}
	if _, ok := r.findByHash(t.TenantID, t.TokenHash); ok {
		return store.ErrConflict
	}
	r.s.resetTickets[key{t.TenantID, t.ID}] = cloneResetTicket(t)
	return nil
}

func (r resetTickets) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.PasswordResetTicket, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneResetTicket(t), nil
}

func (r resetTickets) Consume(_ context.Context, tenantID, tokenHash string, at time.Time) (*store.PasswordResetTicket, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	t, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	if t.UsedAt != nil {
		return cloneResetTicket(t), store.ErrAlreadyUsed
	}
	v := at
	t.UsedAt = &v
	return cloneResetTicket(t), nil
}

func (r resetTickets) DeleteByUser(_ context.Context, tenantID, userID string) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, t := range r.s.resetTickets {
		if k.tenant == tenantID && t.UserID == userID && t.UsedAt == nil {
			delete(r.s.resetTickets, k)
			n++
		}
	}
	return n, nil
}

func (r resetTickets) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, t := range r.s.resetTickets {
		if !t.ExpiresAt.After(before) {
			delete(r.s.resetTickets, k)
			n++
		}
	}
	return n, nil
}
