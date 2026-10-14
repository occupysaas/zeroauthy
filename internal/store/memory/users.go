package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type users struct{ s *Store }

func (r users) Create(_ context.Context, u *store.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{u.TenantID, u.UserID}
	if _, ok := r.s.users[k]; ok || r.loginTaken(u) {
		return store.ErrConflict
	}
	r.s.users[k] = cloneUser(u)
	return nil
}

func (r users) Get(_ context.Context, tenantID, userID string) (*store.User, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (r users) FindByLogin(_ context.Context, tenantID, connection, login string) (*store.User, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	if login == "" {
		return nil, store.ErrNotFound
	}
	for k, u := range r.s.users {
		if k.tenant == tenantID && onConnection(u, connection) && (u.Email == login || u.Username == login) {
			return cloneUser(u), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r users) Update(_ context.Context, u *store.User) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k := key{u.TenantID, u.UserID}
	if _, ok := r.s.users[k]; !ok {
		return store.ErrNotFound
	}
	if r.loginTaken(u) {
		return store.ErrConflict
	}
	r.s.users[k] = cloneUser(u)
	return nil
}

func (r users) RecordLogin(_ context.Context, tenantID, userID string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return store.ErrNotFound
	}
	t := at
	u.LastLogin = &t
	u.LoginsCount++
	return nil
}

// loginTaken reports whether another user shares a connection with u and
// has the same non-empty email or username. The caller holds the lock.
func (r users) loginTaken(u *store.User) bool {
	for k, o := range r.s.users {
		if k.tenant != u.TenantID || k.id == u.UserID {
			continue
		}
		for _, id := range u.Identities {
			if !onConnection(o, id.Connection) {
				continue
			}
			if (u.Email != "" && o.Email == u.Email) || (u.Username != "" && o.Username == u.Username) {
				return true
			}
		}
	}
	return false
}

func onConnection(u *store.User, connection string) bool {
	for _, id := range u.Identities {
		if id.Connection == connection {
			return true
		}
	}
	return false
}
