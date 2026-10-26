package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type operators struct{ s *Store }

func cloneOperator(o *store.Operator) *store.Operator {
	c := *o
	c.Tenants = slices.Clone(o.Tenants)
	return &c
}

func (r operators) Get(_ context.Context, tenantID, userID string) (*store.Operator, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	o, ok := r.s.operators[key{tenantID, userID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneOperator(o), nil
}

func (r operators) Upsert(_ context.Context, o *store.Operator) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{o.TenantID, o.UserID}
	c := cloneOperator(o)
	if old, ok := r.s.operators[k]; ok {
		c.CreatedAt = old.CreatedAt
	}
	r.s.operators[k] = c
	return nil
}

func (r operators) List(_ context.Context, tenantID string) ([]*store.Operator, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var out []*store.Operator
	for k, o := range r.s.operators {
		if k.tenant == tenantID {
			out = append(out, cloneOperator(o))
		}
	}
	slices.SortFunc(out, func(a, b *store.Operator) int { return strings.Compare(a.UserID, b.UserID) })
	return out, nil
}

func (r operators) Delete(_ context.Context, tenantID, userID string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tenantID, userID}
	if _, ok := r.s.operators[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.operators, k)
	r.s.deleteOperatorEmailClaims(userID)
	return nil
}
