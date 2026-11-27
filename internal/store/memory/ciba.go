package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// The memory store implements store.CIBAStore (Plan 41c).

func (s *Store) CreateCIBARequest(_ context.Context, r *store.CIBARequest) error {
	s.lock()
	defer s.unlock()
	k := key{r.TenantID, r.IDHash}
	if _, ok := s.cibaRequests[k]; ok {
		return store.ErrConflict
	}
	for ck, other := range s.cibaRequests {
		if ck.tenant == r.TenantID && other.TicketHash == r.TicketHash {
			return store.ErrConflict
		}
	}
	s.cibaRequests[k] = r.Clone()
	return nil
}

func (s *Store) GetCIBARequest(_ context.Context, tid, idHash string) (*store.CIBARequest, error) {
	s.readLock()
	defer s.readUnlock()
	r, ok := s.cibaRequests[key{tid, idHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return r.Clone(), nil
}

func (s *Store) GetCIBARequestByTicket(_ context.Context, tid, ticketHash string) (*store.CIBARequest, error) {
	s.readLock()
	defer s.readUnlock()
	for k, r := range s.cibaRequests {
		if k.tenant == tid && r.TicketHash == ticketHash {
			return r.Clone(), nil
		}
	}
	return nil, store.ErrNotFound
}

func (s *Store) DecideCIBARequest(_ context.Context, tid, idHash string, dec store.CIBADecision) (*store.CIBARequest, error) {
	s.lock()
	defer s.unlock()
	r, ok := s.cibaRequests[key{tid, idHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if r.Status != store.CIBAPending {
		return r.Clone(), store.ErrAlreadyUsed
	}
	r.Status = dec.Status
	if dec.Status == store.CIBAApproved {
		r.GrantedScopes, r.ActionEffects = append([]string(nil), dec.GrantedScopes...), append([]byte(nil), dec.ActionEffects...)
		r.AuthTime, r.MFAAt = dec.AuthTime, dec.MFAAt
	}
	return r.Clone(), nil
}

func (s *Store) PollCIBARequest(_ context.Context, tid, idHash, clientID string, at time.Time) (store.CIBAPoll, *store.CIBARequest, error) {
	s.lock()
	defer s.unlock()
	r, ok := s.cibaRequests[key{tid, idHash}]
	if !ok || r.ClientID != clientID {
		return 0, nil, store.ErrNotFound
	}
	p := store.PollCIBA(r, at)
	return p, r.Clone(), nil
}

func (s *Store) CountPendingCIBARequests(_ context.Context, tid string, now time.Time) (int, error) {
	s.readLock()
	defer s.readUnlock()
	n := 0
	for k, r := range s.cibaRequests {
		if k.tenant == tid && r.Status == store.CIBAPending && r.ExpiresAt.After(now.Add(-store.CIBAPendingWindow)) {
			n++
		}
	}
	return n, nil
}

func (s *Store) DeleteExpiredCIBARequests(_ context.Context, before time.Time) (int, error) {
	s.lock()
	defer s.unlock()
	n := 0
	for k, r := range s.cibaRequests {
		if !r.ExpiresAt.After(before) {
			delete(s.cibaRequests, k)
			n++
		}
	}
	return n, nil
}
