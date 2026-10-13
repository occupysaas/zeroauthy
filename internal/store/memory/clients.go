package memory

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clients struct{ s *Store }

func (r clients) Create(_ context.Context, c *store.Client) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ClientID}
	if _, ok := r.s.clients[k]; ok {
		return store.ErrConflict
	}
	r.s.clients[k] = cloneClient(c)
	return nil
}

func (r clients) Get(_ context.Context, tenantID, clientID string) (*store.Client, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.clients[key{tenantID, clientID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (r clients) Update(_ context.Context, c *store.Client) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{c.TenantID, c.ClientID}
	if _, ok := r.s.clients[k]; !ok {
		return store.ErrNotFound
	}
	r.s.clients[k] = cloneClient(c)
	return nil
}

func (r clients) Delete(_ context.Context, tenantID, clientID string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{tenantID, clientID}
	if _, ok := r.s.clients[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.clients, k)
	return nil
}
