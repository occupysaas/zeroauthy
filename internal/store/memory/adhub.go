package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The memory store implements store.ADHubStore (Plan 38a).

func adSessionKey(tid, cid, sid string) key { return key{tid, cid + "\x00" + sid} }

func (s *Store) CreateADProvisioning(_ context.Context, p *store.ADProvisioning) error {
	if p == nil || p.TenantID == "" || p.ConnectionID == "" || p.TicketHash == "" {
		return store.ErrInvalid
	}
	s.lock()
	defer s.unlock()
	k := key{p.TenantID, p.ConnectionID}
	if _, ok := s.adProvisionings[k]; ok {
		return store.ErrConflict
	}
	for _, o := range s.adProvisionings {
		if o.TenantID == p.TenantID && o.TicketHash == p.TicketHash {
			return store.ErrConflict
		}
	}
	s.adProvisionings[k] = p.Clone()
	return nil
}

func (s *Store) GetADProvisioning(_ context.Context, tid, cid string) (*store.ADProvisioning, error) {
	s.readLock()
	defer s.readUnlock()
	p, ok := s.adProvisionings[key{tid, cid}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return p.Clone(), nil
}

func (s *Store) FindADProvisioning(_ context.Context, tid, hash string) (*store.ADProvisioning, error) {
	s.readLock()
	defer s.readUnlock()
	for _, p := range s.adProvisionings {
		if p.TenantID == tid && p.TicketHash == hash && hash != "" {
			return p.Clone(), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) PutADHubSession(_ context.Context, sess *store.ADHubSession) error {
	if sess == nil || sess.TenantID == "" || sess.ConnectionID == "" || sess.SessionID == "" {
		return store.ErrInvalid
	}
	s.lock()
	defer s.unlock()
	s.adSessions[adSessionKey(sess.TenantID, sess.ConnectionID, sess.SessionID)] = sess.Clone()
	return nil
}

func (s *Store) DeleteADHubSession(_ context.Context, tid, cid, sid string) error {
	s.lock()
	defer s.unlock()
	delete(s.adSessions, adSessionKey(tid, cid, sid))
	return nil
}

func (s *Store) ListADHubSessions(_ context.Context, tid, cid string, seenAfter time.Time) ([]*store.ADHubSession, error) {
	s.readLock()
	defer s.readUnlock()
	out := []*store.ADHubSession{}
	for _, sess := range s.adSessions {
		if sess.TenantID == tid && sess.ConnectionID == cid && sess.LastSeenAt.After(seenAfter) {
			out = append(out, sess.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *store.ADHubSession) int {
		if c := b.ConnectedAt.Compare(a.ConnectedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.SessionID, b.SessionID)
	})
	return out, nil
}

func (s *Store) PurgeADHubSessions(_ context.Context, before time.Time, limit int) (int, error) {
	s.lock()
	defer s.unlock()
	n := 0
	for k, sess := range s.adSessions {
		if n >= limit {
			break
		}
		if sess.LastSeenAt.Before(before) {
			delete(s.adSessions, k)
			n++
		}
	}
	return n, nil
}

// dropConnectionADHub removes a connection's AD/LDAP rows, with the lock held.
func (s *Store) dropConnectionADHub(tid, cid string) {
	delete(s.adProvisionings, key{tid, cid})
	for k, sess := range s.adSessions {
		if sess.TenantID == tid && sess.ConnectionID == cid {
			delete(s.adSessions, k)
		}
	}
}
