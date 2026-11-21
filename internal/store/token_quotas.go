package store

import (
	"context"
	"math"
	"time"
)

type TokenQuota struct {
	Enforce         bool
	PerHour, PerDay int
}

type DefaultTokenQuota struct{ Clients, Organizations *TokenQuota }

type QuotaSubject struct {
	Kind, ID string
	Quota    TokenQuota
}
type QuotaBucket struct {
	Name             string
	Limit, Remaining int
	Reset            time.Time
	// CrossedThresholds contains newly reached warning percentages (60, 80,
	// 100), in ascending order. Only a successful Consume can claim these,
	// once per tenant, subject, bucket and UTC window, even if limits change.
	CrossedThresholds []int
}
type QuotaState struct {
	Subject  QuotaSubject
	Buckets  []QuotaBucket // per_hour, then per_day, omitting unconfigured limits
	Exceeded bool          // this enforced subject would refuse the requested increment
}

type TokenQuotas interface {
	// Consume checks every subject before changing any. On refusal all
	// counters and warning claims retain their previous values. The states
	// preserve input order and describe usage after the decision.
	Consume(ctx context.Context, tid string, subjects []QuotaSubject, now time.Time) ([]QuotaState, error)
	// Peek shows current remaining counts and whether an increment would fail.
	Peek(ctx context.Context, tid string, subjects []QuotaSubject, now time.Time) ([]QuotaState, error)
	PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error)
}

// QuotaWindows validates the complete request and constructs hour/day windows
// in response order, before a driver takes locks or changes counters.
func QuotaWindows(tid string, subjects []QuotaSubject, now time.Time) ([]QuotaState, error) {
	if tid == "" {
		return nil, ErrInvalid
	}
	states := make([]QuotaState, len(subjects))
	seen := map[[2]string]bool{}
	for i, s := range subjects {
		key := [2]string{s.Kind, s.ID}
		if s.ID == "" || (s.Kind != "client" && s.Kind != "organization") || seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		states[i].Subject = s
		for _, w := range []struct {
			name   string
			period time.Duration
			limit  int
		}{{"per_hour", time.Hour, s.Quota.PerHour}, {"per_day", 24 * time.Hour, s.Quota.PerDay}} {
			if w.limit < 0 || w.limit > math.MaxInt32 {
				return nil, ErrInvalid
			}
			if w.limit != 0 {
				states[i].Buckets = append(states[i].Buckets, QuotaBucket{Name: w.name, Limit: w.limit, Remaining: w.limit, Reset: now.UTC().Truncate(w.period).Add(w.period)})
			}
		}
	}
	return states, nil
}

// ClaimWarnings records warnings reached at the committed count. A limit
// change in an open window must preserve previously issued warning bits.
func (b *QuotaBucket) ClaimWarnings(count int64, warned uint8) uint8 {
	for i, pct := range [...]int64{60, 80, 100} {
		bit := uint8(1 << i)
		if count >= (int64(b.Limit)*pct+99)/100 && warned&bit == 0 {
			warned |= bit
			b.CrossedThresholds = append(b.CrossedThresholds, int(pct))
		}
	}
	return warned
}
