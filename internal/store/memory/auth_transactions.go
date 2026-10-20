package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type authTransactions struct{ s *Store }

func (r authTransactions) Create(_ context.Context, t *store.AuthTransaction) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{t.TenantID, t.ID}
	if _, ok := r.s.transactions[k]; ok {
		return store.ErrConflict
	}
	r.s.transactions[k] = cloneAuthTransaction(t)
	return nil
}

func (r authTransactions) Get(_ context.Context, tenantID, id string) (*store.AuthTransaction, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.s.transactions[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneAuthTransaction(t), nil
}

func (r authTransactions) Delete(_ context.Context, tenantID, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tenantID, id}
	if _, ok := r.s.transactions[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.transactions, k)
	return nil
}

func (r authTransactions) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, t := range r.s.transactions {
		if !t.ExpiresAt.After(before) {
			delete(r.s.transactions, k)
			n++
		}
	}
	return n, nil
}
