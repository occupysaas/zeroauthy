package memory

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

func (s *Store) UseGlobalRevocationJTI(_ context.Context, tid, connection, jti string, exp, now time.Time) error {
	if tid == "" || connection == "" || jti == "" || len(jti) > 256 || !exp.After(now) {
		return store.ErrInvalid
	}
	s.lock()
	defer s.unlock()
	k := jtiKey(tid, connection, jti)
	if old, ok := s.globalRevocationJTIs[k]; ok && old.After(now) {
		return store.ErrConflict
	}
	s.globalRevocationJTIs[k] = exp
	return nil
}
func (s *Store) PurgeGlobalRevocationJTIs(_ context.Context, before time.Time, limit int) (int, error) {
	s.lock()
	defer s.unlock()
	n := 0
	for k, exp := range s.globalRevocationJTIs {
		if n >= limit {
			break
		}
		if !exp.After(before) {
			delete(s.globalRevocationJTIs, k)
			n++
		}
	}
	return n, nil
}
func (s *Store) FindByFederatedEmail(ctx context.Context, tid, connection, email string) (*store.User, error) {
	s.readLock()
	defer s.readUnlock()
	conn := s.connections[key{tid, connection}]
	if conn == nil {
		return nil, store.ErrNotFound
	}
	var found *store.User
	for k, owner := range s.fedIdentities {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if k.TenantID != tid || k.ConnectionID != connection {
			continue
		}
		u := s.users[key{tid, owner}]
		if store.FederatedEmailMatches(u, conn.Name, email) {
			if found != nil && found.UserID != u.UserID {
				return nil, store.ErrNotFound
			} // ambiguous identities do not select an account
			found = u
		}
	}
	if found == nil {
		return nil, store.ErrNotFound
	}
	return cloneUser(found), nil
}
