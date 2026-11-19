package store

import (
	"context"
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
