package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// UseSAMLAssertion implements store.SAMLReplayStore.
func (s *Store) UseSAMLAssertion(_ context.Context, tid, connection, id string, exp, now time.Time) error {
	if tid == "" || connection == "" || id == "" || len(id) > 1024 || !exp.After(now) {
		return store.ErrInvalid
	}
	s.lock()
	defer s.unlock()
	k := jtiKey(tid, connection, id)
	if old, ok := s.samlAssertions[k]; ok && old.After(now) {
		return store.ErrConflict
	}
	s.samlAssertions[k] = exp
	return nil
}

// PurgeSAMLAssertions implements store.SAMLReplayStore.
func (s *Store) PurgeSAMLAssertions(_ context.Context, before time.Time, limit int) (int, error) {
	s.lock()
	defer s.unlock()
	n := 0
	for k, exp := range s.samlAssertions {
		if n >= limit {
			break
		}
		if !exp.After(before) {
			delete(s.samlAssertions, k)
			n++
		}
	}
	return n, nil
}
