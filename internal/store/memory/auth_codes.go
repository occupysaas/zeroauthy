package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type authCodes struct{ s *Store }

func (r authCodes) Create(_ context.Context, c *store.AuthCode) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.CodeHash}
	if _, ok := r.s.authCodes[k]; ok {
		return store.ErrConflict
	}
	r.s.authCodes[k] = cloneAuthCode(c)
	return nil
}

func (r authCodes) Consume(_ context.Context, tenantID, codeHash string, at time.Time) (*store.AuthCode, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c, ok := r.s.authCodes[key{tenantID, codeHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if c.UsedAt != nil {
		return cloneAuthCode(c), store.ErrAlreadyUsed
	}
	t := at
	c.UsedAt = &t
	return cloneAuthCode(c), nil
}

func (r authCodes) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	n := 0
	for k, c := range r.s.authCodes {
		if !c.ExpiresAt.After(before) {
			delete(r.s.authCodes, k)
			n++
		}
	}
	return n, nil
}
