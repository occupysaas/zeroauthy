package memory

import (
	"context"
	"math"
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
			for i, pct := range [...]int64{60, 80, 100} {
				bit := uint8(1 << i)
				target := (int64(b.Limit)*pct + 99) / 100
				if c.count >= target && c.warned&bit == 0 {
					c.warned |= bit
					b.CrossedThresholds = append(b.CrossedThresholds, int(pct))
				}
			}
			b.Remaining = max(0, b.Remaining-1)
			r.s.quotaCounters[k] = c
		}
	}
	return states, nil
}

// states checks every bucket without modifying counters. Distinct subjects
// can have the same ID (for example a client and an organization).
func (r tokenQuotas) states(tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, bool, error) {
	if tid == "" {
		return nil, false, store.ErrInvalid
	}
	states := make([]store.QuotaState, len(subjects))
	seen := map[[2]string]bool{}
	refused := false
	for i, s := range subjects {
		id := [2]string{s.Kind, s.ID}
		if s.ID == "" || (s.Kind != "client" && s.Kind != "organization") || seen[id] {
			return nil, false, store.ErrInvalid
		}
		seen[id] = true
		state := store.QuotaState{Subject: s}
		for _, w := range []struct {
			name   string
			period time.Duration
			limit  int
		}{
			{"per_hour", time.Hour, s.Quota.PerHour}, {"per_day", 24 * time.Hour, s.Quota.PerDay},
		} {
			if w.limit < 0 || w.limit > math.MaxInt32 {
				return nil, false, store.ErrInvalid
			}
			if w.limit == 0 {
				continue
			}
			reset := now.UTC().Truncate(w.period).Add(w.period)
			c := r.s.quotaCounters[quotaKey{tid, s.Kind, s.ID, w.name, reset}]
			remaining := int(max(0, int64(w.limit)-c.count))
			if remaining == 0 && s.Quota.Enforce {
				state.Exceeded = true
				refused = true
			}
			state.Buckets = append(state.Buckets, store.QuotaBucket{Name: w.name, Limit: w.limit, Remaining: remaining, Reset: reset})
		}
		states[i] = state
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
