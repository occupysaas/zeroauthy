package memory

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type quotaKey struct {
	tenant, kind, id, bucket string
	reset                    time.Time
}
type quotaCounter struct {
	count  int64
	warned uint8 // bit i marks a claimed 60%, 80% or 100% warning, respectively
}
type tokenQuotas struct{ s *Store }

func (s *Store) TokenQuotas() store.TokenQuotas { return tokenQuotas{s} }

func (r tokenQuotas) Peek(_ context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	states, _, err := r.states(tid, subjects, now)
	return states, err
}

func (r tokenQuotas) Consume(_ context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	r.s.lock()
	defer r.s.unlock()
	states, refused, err := r.states(tid, subjects, now)
	if err != nil || refused {
		return states, err
	}
	for i, s := range states {
		for j := range s.Buckets {
			b := &states[i].Buckets[j]
			k := quotaKey{tid, s.Subject.Kind, s.Subject.ID, b.Name, b.Reset}
			c := r.s.quotaCounters[k]
			c.count++
			c.warned = b.ClaimWarnings(c.count, c.warned)
			b.Remaining = max(0, b.Remaining-1)
			r.s.quotaCounters[k] = c
		}
	}
	return states, nil
}

// states checks every bucket without modifying counters. Distinct subjects
// can have the same ID (for example a client and an organization).
func (r tokenQuotas) states(tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, bool, error) {
	states, err := store.QuotaWindows(tid, subjects, now)
	if err != nil {
		return nil, false, err
	}
	refused := false
	for i := range states {
		s := &states[i]
		for j := range s.Buckets {
			b := &s.Buckets[j]
			c := r.s.quotaCounters[quotaKey{tid, s.Subject.Kind, s.Subject.ID, b.Name, b.Reset}]
			b.Remaining = int(max(0, int64(b.Limit)-c.count))
			if b.Remaining == 0 && s.Subject.Quota.Enforce {
				s.Exceeded = true
				refused = true
			}
		}
	}

	return states, refused, nil
}

func (r tokenQuotas) PurgeBefore(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k := range r.s.quotaCounters {
		if n >= limit {
			break
		}
		if !k.reset.After(before) {
			delete(r.s.quotaCounters, k)
			n++
		}
	}
	return n, nil
}
