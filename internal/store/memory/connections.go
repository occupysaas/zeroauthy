package memory

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type connections struct{ s *Store }

func (r connections) Create(_ context.Context, c *store.Connection) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{c.TenantID, c.ID}
	if _, ok := r.s.connections[k]; ok || r.nameTaken(c) {
		return store.ErrConflict
	}
	r.s.connections[k] = cloneConnection(c)
	return nil
}

func (r connections) Get(_ context.Context, tenantID, id string) (*store.Connection, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	c, ok := r.s.connections[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneConnection(c), nil
}

func (r connections) GetByName(_ context.Context, tenantID, name string) (*store.Connection, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, c := range r.s.connections {
		if k.tenant == tenantID && c.Name == name {
			return cloneConnection(c), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r connections) Update(_ context.Context, c *store.Connection) error {
	r.s.lock()
	defer r.s.unlock()
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

func (r connections) List(_ context.Context, tenantID string, f store.ConnectionFilter, p store.Page) ([]*store.Connection, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.Connection
	for k, c := range r.s.connections {
		if k.tenant == tenantID && (f.Name == "" || c.Name == f.Name) &&
			(len(f.Strategies) == 0 || slices.Contains(f.Strategies, c.Strategy)) {
			all = append(all, c)
		}
	}
	slices.SortFunc(all, func(a, b *store.Connection) int {
		return cmp.Or(strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.ID, b.ID))
	})
	total := len(all)
	all = all[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	out := make([]*store.Connection, len(all))
	for i, c := range all {
		out[i] = cloneConnection(c)
	}
	return out, total, nil
}

func (r connections) Delete(_ context.Context, tenantID, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tenantID, id}
	c, ok := r.s.connections[k]
	if !ok {
		return store.ErrNotFound
	}
	if p := r.s.protection[tenantID]; p != nil {
		p.Clear(store.ProtectionFilter{ConnectionID: id})
	}
	delete(r.s.connections, k)
	if t, ok := r.s.tenants[tenantID]; ok && t.DefaultDirectory == c.Name {
		t.DefaultDirectory = ""
	}
	gone := map[string]bool{}
	for uk, u := range r.s.users {
		if uk.tenant != tenantID {
			continue
		}
		switch del, strip := u.ConnectionDeleteEffect(c.Name); {
		case del:
			gone[uk.id] = true
		case strip:
			u.WithoutLinkedOn(c.Name)
			u.Version++
		}
	}
	r.s.deleteUsers(tenantID, gone)
	return nil
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
