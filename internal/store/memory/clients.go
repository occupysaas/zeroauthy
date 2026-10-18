package memory

import (
	"context"
	"slices"
	"strings"

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
	for gk, g := range r.s.clientGrants {
		if gk.tenant == tenantID && g.ClientID == clientID {
			delete(r.s.clientGrants, gk)
		}
	}
	for gk, g := range r.s.userGrants {
		if gk.tenant == tenantID && g.ClientID == clientID {
			delete(r.s.userGrants, gk)
		}
	}
	for tk, t := range r.s.refreshTokens {
		if tk.tenant == tenantID && t.ClientID == clientID {
			delete(r.s.refreshTokens, tk)
		}
	}
	return nil
}

func (r clients) List(_ context.Context, tenantID string) ([]*store.Client, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.Client
	for k, c := range r.s.clients {
		if k.tenant == tenantID {
			out = append(out, cloneClient(c))
		}
	}
	slices.SortFunc(out, func(a, b *store.Client) int { return strings.Compare(a.ClientID, b.ClientID) })
	return out, nil
}
