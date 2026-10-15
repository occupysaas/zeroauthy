package memory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type signingKeys struct{ s *Store }

func (r signingKeys) Create(_ context.Context, k *store.SigningKey) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	kk := key{k.TenantID, k.KID}
	if _, ok := r.s.signingKeys[kk]; ok {
		return store.ErrConflict
	}
	if k.Status == store.KeyCurrent || k.Status == store.KeyNext {
		for ok, sk := range r.s.signingKeys {
			if ok.tenant == k.TenantID && sk.Status == k.Status {
				return store.ErrConflict
			}
		}
	}
	r.s.signingKeys[kk] = cloneSigningKey(k)
	return nil
}

func (r signingKeys) List(_ context.Context, tenantID string) ([]*store.SigningKey, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.SigningKey
	for k, sk := range r.s.signingKeys {
		if k.tenant == tenantID {
			out = append(out, cloneSigningKey(sk))
		}
	}
	slices.SortFunc(out, func(a, b *store.SigningKey) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.KID, b.KID)
	})
	return out, nil
}

func (r signingKeys) Rotate(_ context.Context, tenantID string, next *store.SigningKey) error {
	if next.Status != store.KeyNext {
		return errors.New("store: the new key must have status next")
	}
	if next.TenantID != tenantID {
		return fmt.Errorf("memory: rotate needs a key for tenant %q", tenantID)
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.signingKeys[key{tenantID, next.KID}]; ok {
		return store.ErrConflict
	}
	hasNext := false
	for k, sk := range r.s.signingKeys {
		if k.tenant == tenantID && sk.Status == store.KeyNext {
			hasNext = true
		}
	}
	if !hasNext {
		return store.ErrNotFound
	}
	promote := map[store.KeyStatus]store.KeyStatus{
		store.KeyPrevious: store.KeyRevoked,
		store.KeyCurrent:  store.KeyPrevious,
		store.KeyNext:     store.KeyCurrent,
	}
	for k, sk := range r.s.signingKeys {
		if k.tenant != tenantID {
			continue
		}
		if to, ok := promote[sk.Status]; ok {
			sk.Status = to
		}
	}
	r.s.signingKeys[key{tenantID, next.KID}] = cloneSigningKey(next)
	return nil
}
