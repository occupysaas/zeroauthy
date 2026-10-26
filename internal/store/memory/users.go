package memory

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
)

type users struct{ s *Store }

func (r users) Create(_ context.Context, u *store.User) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{u.TenantID, u.UserID}
	if _, ok := r.s.users[k]; ok || r.loginTaken(u) {
		return store.ErrConflict
	}
	nu := cloneUser(u)
	nu.Version = 0
	r.s.users[k] = nu
	return nil
}

func (r users) Get(_ context.Context, tenantID, userID string) (*store.User, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

// GetForUpdate is Get: transactions and writes are serialized by txMu.
func (r users) GetForUpdate(ctx context.Context, tenantID, userID string) (*store.User, error) {
	return r.Get(ctx, tenantID, userID)
}

func (r users) FindByLogin(_ context.Context, tenantID, connection, login string) (*store.User, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if login == "" {
		return nil, store.ErrNotFound
	}
	for k, u := range r.s.users {
		if k.tenant != tenantID {
			continue
		}
		for _, l := range u.LoginKeys() {
			if l.Connection == connection && l.Value == login {
				return cloneUser(u), nil
			}
		}
	}
	return nil, store.ErrNotFound
}

func (r users) Update(_ context.Context, u *store.User) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{u.TenantID, u.UserID}
	if _, ok := r.s.users[k]; !ok {
		return store.ErrNotFound
	}
	if r.loginTaken(u) {
		return store.ErrConflict
	}
	nu := cloneUser(u)
	old := r.s.users[k]
	nu.LastLogin, nu.LoginsCount, nu.LastIP = old.LastLogin, old.LoginsCount, old.LastIP
	nu.Version = old.Version
	if (nu.Blocked && !old.Blocked) || nu.Email != old.Email {
		nu.Version++
	}
	r.s.users[k] = nu
	return nil
}

func (r users) RecordLogin(_ context.Context, tenantID, userID string, at time.Time, ip string) error {
	r.s.lock()
	defer r.s.unlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return store.ErrNotFound
	}
	t := at
	u.LastLogin = &t
	u.LastIP = ip
	u.LoginsCount++
	return nil
}

func (r users) SetPasswordHash(_ context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	return r.setHash(tenantID, userID, connection, hash, at, false)
}

func (r users) SetPasswordHashIfEmpty(_ context.Context, tenantID, userID, connection, hash string, at time.Time) error {
	return r.setHash(tenantID, userID, connection, hash, at, true)
}

func (r users) setHash(tenantID, userID, connection, hash string, at time.Time, onlyIfEmpty bool) error {
	r.s.lock()
	defer r.s.unlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return store.ErrNotFound
	}
	for i := range u.Identities {
		// The user's own identity; a linked one keeps its hash (D-0043).
		if u.Identities[i].Connection == connection && !u.Identities[i].Linked() {
			if onlyIfEmpty && (u.Identities[i].PasswordHash != "" || u.Identities[i].ImportedHash != "") {
				return store.ErrConflict
			}
			u.Identities[i].PasswordHash = hash
			u.Identities[i].ImportedHash = ""
			u.UpdatedAt = at
			u.Version++
			return nil
		}
	}
	return store.ErrNotFound
}

func (r users) UpgradeImportedHash(_ context.Context, tenantID, userID, connection, imported, hash string, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return store.ErrNotFound
	}
	for i := range u.Identities {
		if id := &u.Identities[i]; imported != "" && id.Connection == connection && id.ImportedHash == imported {
			id.PasswordHash = hash
			id.ImportedHash = ""
			u.UpdatedAt = at
			u.Version++
			return nil
		}
	}
	return store.ErrConflict
}

func (r users) BumpVersion(_ context.Context, tenantID, userID string) (int64, error) {
	r.s.lock()
	defer r.s.unlock()
	u, ok := r.s.users[key{tenantID, userID}]
	if !ok {
		return 0, store.ErrNotFound
	}
	u.Version++
	return u.Version, nil
}

func (r users) FindByEmail(_ context.Context, tenantID, email string) ([]*store.User, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var out []*store.User
	if email == "" {
		return out, nil
	}
	for k, u := range r.s.users {
		if k.tenant == tenantID && u.Email == email {
			out = append(out, cloneUser(u))
		}
	}
	slices.SortFunc(out, func(a, b *store.User) int { return strings.Compare(a.UserID, b.UserID) })
	return out, nil
}

func (r users) Delete(_ context.Context, tenantID, userID string) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.users[key{tenantID, userID}]; !ok {
		return store.ErrNotFound
	}
	r.s.deleteUsers(tenantID, map[string]bool{userID: true})
	return nil
}

// deleteUsers removes the users and everything that names them. The caller
// holds the lock; Connections.Delete uses it too.
func (s *Store) deleteUsers(tenantID string, gone map[string]bool) {
	for id := range gone {
		s.deleteEmailClaims(tenantID, id)
		if p := s.protection[tenantID]; p != nil {
			if u := s.users[key{tenantID, id}]; u != nil {
				var cs []*store.Connection
				for k, c := range s.connections {
					if k.tenant == tenantID {
						cs = append(cs, c)
					}
				}
				for _, f := range protectionstate.UserFilters(u, cs) {
					p.Clear(f)
				}
			}
		}
		delete(s.users, key{tenantID, id})
		delete(s.passwordHistories, key{tenantID, id})
	}
	for k, v := range s.sessions {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.refreshTokens {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.refreshTokens, k)
		}
	}
	for k, v := range s.userGrants {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.userGrants, k)
		}
	}
	for k, v := range s.resetTickets {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.resetTickets, k)
		}
	}
	for k, v := range s.verifyTickets {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.verifyTickets, k)
		}
	}
	for k, v := range s.authCodes {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.authCodes, k)
		}
	}
	for id := range gone {
		delete(s.operators, key{tenantID, id})
	}
	for k, v := range s.deviceCodes {
		if k.tenant == tenantID && gone[v.UserID] {
			delete(s.deviceCodes, k)
		}
	}
}

// loginTaken reports whether another user has one of u's logins (the same
// email or username on the same connection; see store.User.LoginKeys). The
// caller holds the lock.
func (r users) loginTaken(u *store.User) bool {
	mine := u.LoginKeys()
	if len(mine) == 0 {
		return false
	}
	for k, o := range r.s.users {
		if k.tenant != u.TenantID || k.id == u.UserID {
			continue
		}
		for _, l := range o.LoginKeys() {
			if slices.Contains(mine, l) {
				return true
			}
		}
	}
	return false
}

func (r users) List(_ context.Context, tenantID string, q *store.UserQuery, s store.UserSort, p store.Page) ([]*store.User, int, error) {
	m, err := store.NewUserMatcher(q)
	if err != nil {
		return nil, 0, err
	}
	if err := s.Validate(); err != nil {
		return nil, 0, err
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.User
	for k, u := range r.s.users {
		if k.tenant == tenantID && m.Match(u) {
			all = append(all, u)
		}
	}
	slices.SortFunc(all, func(a, b *store.User) int { return store.CompareUsers(a, b, s) })
	total := len(all)
	all = all[min(max(p.Offset, 0), total):]
	if p.Limit > 0 && len(all) > p.Limit {
		all = all[:p.Limit]
	}
	out := make([]*store.User, len(all))
	for i, u := range all {
		out[i] = cloneUser(u)
	}
	return out, total, nil
}
