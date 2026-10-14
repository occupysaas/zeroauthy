package memory

import (
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type connections struct{ s *Store }

func (r connections) Create(_ context.Context, c *store.Connection) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ID}
	if _, ok := r.s.connections[k]; ok || r.nameTaken(c) {
		return store.ErrConflict
	}
	r.s.connections[k] = cloneConnection(c)
	return nil
}

func (r connections) Get(_ context.Context, tenantID, id string) (*store.Connection, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.connections[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneConnection(c), nil
}

func (r connections) GetByName(_ context.Context, tenantID, name string) (*store.Connection, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for k, c := range r.s.connections {
		if k.tenant == tenantID && c.Name == name {
			return cloneConnection(c), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r connections) Update(_ context.Context, c *store.Connection) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ID}
	if _, ok := r.s.connections[k]; !ok {
		return store.ErrNotFound
	}
	if r.nameTaken(c) {
		return store.ErrConflict
	}
	r.s.connections[k] = cloneConnection(c)
	return nil
}

func (r connections) List(_ context.Context, tenantID string) ([]*store.Connection, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.Connection
	for k, c := range r.s.connections {
		if k.tenant == tenantID {
			out = append(out, cloneConnection(c))
		}
	}
	slices.SortFunc(out, func(a, b *store.Connection) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// nameTaken is called with the lock held.
func (r connections) nameTaken(c *store.Connection) bool {
	for k, o := range r.s.connections {
		if k.tenant == c.TenantID && k.id != c.ID && o.Name == c.Name {
			return true
		}
	}
	return false
}
