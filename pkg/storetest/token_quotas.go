package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testTokenQuotas(t *testing.T, newStore Factory) {
	ctx := context.Background()
	start := time.Date(2026, 1, 3, 22, 59, 0, 0, time.UTC)
	t.Run("QuotaConsume", func(t *testing.T) {
		repo := open(t, newStore).TokenQuotas()
		subjects := []store.QuotaSubject{
			{Kind: "client", ID: "app", Quota: store.TokenQuota{PerHour: 5, PerDay: 10, Enforce: true}},
			{Kind: "organization", ID: "org", Quota: store.TokenQuota{PerHour: 1, Enforce: true}},
		}
		state, err := repo.Consume(ctx, "ten_a", subjects, start)
		mustNoErr(t, err)
		mustEqual(t, state[0].Buckets[0], store.QuotaBucket{Name: "per_hour", Limit: 5, Remaining: 4, Reset: start.Add(time.Minute)})
		mustEqual(t, state[0].Buckets[1], store.QuotaBucket{Name: "per_day", Limit: 10, Remaining: 9, Reset: start.Add(61 * time.Minute)})
		mustEqual(t, state[1].Buckets[0].CrossedThresholds, []int{60, 80, 100})
		mustEqual(t, state[1].Exceeded, false)
		state, err = repo.Consume(ctx, "ten_a", subjects, start)
		mustNoErr(t, err)
		mustEqual(t, state[1].Exceeded, true)
		mustEqual(t, state[0].Buckets[0].Remaining, 4)
		mustEqual(t, state[0].Buckets[1].Remaining, 9)
		mustEqual(t, len(state[1].Buckets[0].CrossedThresholds), 0)
		subjects[1].Quota.Enforce = false
		state, err = repo.Consume(ctx, "ten_a", subjects, start)
		mustNoErr(t, err)
		mustEqual(t, state[0].Buckets[0].Remaining, 3)
		mustEqual(t, state[1].Exceeded, false)
		mustEqual(t, state[1].Buckets[0].Remaining, 0)
		mustEqual(t, len(state[1].Buckets[0].CrossedThresholds), 0)
		for i, threshold := range []int{60, 80, 100} {
			state, err = repo.Consume(ctx, "ten_a", subjects, start)
			mustNoErr(t, err)
			mustEqual(t, state[0].Buckets[0].CrossedThresholds, []int{threshold})
			mustEqual(t, state[0].Buckets[0].Remaining, 2-i)
		}
		// Changing a limit midway through a window must not emit the same warning twice.
		subjects[0].Quota.PerHour = 10
		state, err = repo.Consume(ctx, "ten_a", subjects, start)
		mustNoErr(t, err)
		mustEqual(t, len(state[0].Buckets[0].CrossedThresholds), 0)
		state, err = repo.Peek(ctx, "ten_a", subjects, start.Add(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, state[0].Buckets[0].Remaining, 10)
		mustEqual(t, state[0].Buckets[1].Remaining, 4)
		state, err = repo.Peek(ctx, "ten_a", subjects, start.Add(61*time.Minute))
		mustNoErr(t, err)
		mustEqual(t, state[0].Buckets[1].Remaining, 10)
		state, err = repo.Peek(ctx, "ten_b", subjects, start)
		mustNoErr(t, err)
		mustEqual(t, state[0].Buckets[1].Remaining, 10)
		n, err := repo.PurgeBefore(ctx, start.Add(time.Minute), 1)
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		n, err = repo.PurgeBefore(ctx, start.Add(time.Minute), 10)
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		n, err = repo.PurgeBefore(ctx, start.Add(61*time.Minute), 10)
		mustNoErr(t, err)
		mustEqual(t, n, 1)
	})
	t.Run("QuotaConcurrent", func(t *testing.T) {
		repo := open(t, newStore).TokenQuotas()
		subs := []store.QuotaSubject{{Kind: "client", ID: "app", Quota: store.TokenQuota{Enforce: true, PerHour: 10}}}
		type outcome struct {
			allowed  bool
			warnings []int
		}
		out := make([]outcome, 50)
		errs := parallel(len(out), func(i int) error {
			states, err := repo.Consume(ctx, "ten_a", subs, start)
			if err == nil {
				out[i] = outcome{!states[0].Exceeded, states[0].Buckets[0].CrossedThresholds}
			}
			return err
		})
		wins := 0
		counts := map[int]int{}
		for i, err := range errs {
			mustNoErr(t, err)
			if out[i].allowed {
				wins++
			}
			for _, pct := range out[i].warnings {
				counts[pct]++
			}
		}
		mustEqual(t, wins, 10)
		mustEqual(t, counts, map[int]int{60: 1, 80: 1, 100: 1})
	})
	t.Run("Rollback", func(t *testing.T) {
		s := open(t, newStore)
		sub := []store.QuotaSubject{{Kind: "client", ID: "app", Quota: store.TokenQuota{PerDay: 1, Enforce: true}}}
		rollback := errors.New("rollback")
		err := s.WithTx(ctx, func(tx store.Store) error {
			_, err := tx.TokenQuotas().Consume(ctx, "ten_a", sub, start)
			if err != nil {
				return err
			}
			return rollback
		})
		mustErrIs(t, err, rollback)
		state, err := s.TokenQuotas().Consume(ctx, "ten_a", sub, start)
		mustNoErr(t, err)
		mustEqual(t, state[0].Exceeded, false)
		mustEqual(t, state[0].Buckets[0].CrossedThresholds, []int{60, 80, 100})
	})
}
