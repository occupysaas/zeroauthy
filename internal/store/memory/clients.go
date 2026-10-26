package memory

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clients struct{ s *Store }

func (r clients) Create(_ context.Context, c *store.Client) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{c.TenantID, c.ClientID}
	if _, ok := r.s.clients[k]; ok {
		return store.ErrConflict
	}
	r.s.clients[k] = cloneClient(c)
	return nil
}

func (r clients) Get(_ context.Context, tenantID, clientID string) (*store.Client, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	c, ok := r.s.clients[key{tenantID, clientID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (r clients) Update(_ context.Context, c *store.Client) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{c.TenantID, c.ClientID}
	if _, ok := r.s.clients[k]; !ok {
		return store.ErrNotFound
	}
	r.s.clients[k] = cloneClient(c)
	return nil
}

func (r clients) Delete(_ context.Context, tenantID, clientID string) error {
	r.s.lock()
	defer r.s.unlock()
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

func (r clients) List(_ context.Context, tenantID string, f store.ClientFilter, p store.Page) ([]*store.Client, int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.Client
	for k, c := range r.s.clients {
		if k.tenant == tenantID && (len(f.AppTypes) == 0 || slices.Contains(f.AppTypes, string(c.AppType))) &&
			(f.IsFirstParty == nil || c.IsFirstParty == *f.IsFirstParty) {
			all = append(all, c)
		}
	}
	slices.SortFunc(all, func(a, b *store.Client) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ClientID, b.ClientID))
	})
	total := len(all)
	all = all[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	out := make([]*store.Client, len(all))
	for i, c := range all {
		out[i] = cloneClient(c)
	}
	return out, total, nil
}
