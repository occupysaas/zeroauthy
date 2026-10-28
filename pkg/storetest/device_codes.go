package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newDeviceCode(tenantID, deviceHash, userHash string) *store.DeviceCode {
	return &store.DeviceCode{
		TenantID: tenantID, DeviceCodeHash: deviceHash, UserCodeHash: userHash,
		ClientID: "tv", Scopes: []string{"openid", "profile"}, Audience: "https://api.test",
		Status:    store.DeviceCodePending,
		ExpiresAt: ts(10 * time.Minute), CreatedAt: ts(0),
	}
}

func approve(t *testing.T, s store.Store, tenantID, deviceHash string) {
	t.Helper()
	_, err := s.DeviceCodes().Decide(context.Background(), tenantID, deviceHash,
		store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: "u1", GrantedScopes: []string{"openid"}})
	mustNoErr(t, err)
}

func testDeviceCodes(t *testing.T, newStore Factory) {
	ctx := context.Background()
	poll := func(t *testing.T, s store.Store, hash string, at time.Time) store.DevicePoll {
		t.Helper()
		p, err := s.DeviceCodes().Poll(ctx, "ten_a", hash, at)
		mustNoErr(t, err)
		return p
	}

	t.Run("CreateGet", func(t *testing.T) {
		s := open(t, newStore)
		in := newDeviceCode("ten_a", "d1", "u1")
		mustNoErr(t, s.DeviceCodes().Create(ctx, in))
		in.Scopes[0] = "mutated" // Create copies its input
		want := newDeviceCode("ten_a", "d1", "u1")
		got, err := s.DeviceCodes().Get(ctx, "ten_a", "d1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		byUser, err := s.DeviceCodes().GetByUserCode(ctx, "ten_a", "u1")
		mustNoErr(t, err)
		mustEqual(t, byUser, want)

		got.Scopes[0] = "mutated"
		again, err := s.DeviceCodes().Get(ctx, "ten_a", "d1")
		mustNoErr(t, err)
		mustEqual(t, again, want)

		_, err = s.DeviceCodes().Get(ctx, "ten_b", "d1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.DeviceCodes().GetByUserCode(ctx, "ten_a", "nope")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("CreateConflict", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		mustErrIs(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u2")), store.ErrConflict)
		mustErrIs(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d2", "u1")), store.ErrConflict)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_b", "d3", "u1")))
	})

	t.Run("DecideOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		got, err := s.DeviceCodes().Decide(ctx, "ten_a", "d1",
			store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: "u1", GrantedScopes: []string{"openid"}})
		mustNoErr(t, err)
		mustEqual(t, got.Status, store.DeviceCodeApproved)
		mustEqual(t, got.UserID, "u1")
		mustEqual(t, got.GrantedScopes, []string{"openid"})
		mustEqual(t, got.ActionEffects == nil, true)

		again, err := s.DeviceCodes().Decide(ctx, "ten_a", "d1", store.DeviceDecision{Status: store.DeviceCodeDenied})
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.Status, store.DeviceCodeApproved)
		stored, err := s.DeviceCodes().Get(ctx, "ten_a", "d1")
		mustNoErr(t, err)
		mustEqual(t, stored.Status, store.DeviceCodeApproved)

		_, err = s.DeviceCodes().Decide(ctx, "ten_a", "nope", store.DeviceDecision{Status: store.DeviceCodeDenied})
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("DecideActionEffects", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		got, err := s.DeviceCodes().Decide(ctx, "ten_a", "d1", store.DeviceDecision{Status: store.DeviceCodeApproved,
			UserID: "u1", GrantedScopes: []string{"openid"}, ActionEffects: sealedEffects()})
		mustNoErr(t, err)
		mustEqual(t, got.ActionEffects, sealedEffects())
		p, err := s.DeviceCodes().Poll(ctx, "ten_a", "d1", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, p.Code.ActionEffects, sealedEffects())
		stored, err := s.DeviceCodes().Get(ctx, "ten_a", "d1")
		mustNoErr(t, err)
		mustEqual(t, stored.ActionEffects, sealedEffects())
	})

	t.Run("ConcurrentDecide", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		errs := parallel(10, func(i int) error {
			dec := store.DeviceDecision{Status: store.DeviceCodeDenied}
			if i%2 == 0 {
				dec = store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: "u1", GrantedScopes: []string{"openid"}}
			}
			_, err := s.DeviceCodes().Decide(ctx, "ten_a", "d1", dec)
			return err
		})
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAlreadyUsed):
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		mustEqual(t, ok, 1)
	})

	t.Run("PollPending", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		first := ts(time.Second)
		p := poll(t, s, "d1", first)
		mustEqual(t, p.Outcome, store.PollPending)
		mustEqual(t, p.Code.LastPolledAt.Equal(first), true)

		p = poll(t, s, "d1", first.Add(300*time.Millisecond))
		mustEqual(t, p.Outcome, store.PollSlowDown)
		mustEqual(t, p.Code.LastPolledAt.Equal(first), true) // not advanced

		p = poll(t, s, "d1", first.Add(time.Second))
		mustEqual(t, p.Outcome, store.PollPending)
		mustEqual(t, p.Code.LastPolledAt.Equal(first.Add(time.Second)), true)

		_, err := s.DeviceCodes().Poll(ctx, "ten_a", "nope", first)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("PollBoundary", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		mustEqual(t, poll(t, s, "d1", ts(time.Second)).Outcome, store.PollPending)
		mustEqual(t, poll(t, s, "d1", ts(time.Second+store.MinPollGap)).Outcome, store.PollPending)
	})

	t.Run("PollApprovedOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		approve(t, s, "ten_a", "d1")
		p := poll(t, s, "d1", ts(time.Second))
		mustEqual(t, p.Outcome, store.PollApproved)
		mustEqual(t, p.Code.Status, store.DeviceCodeConsumed)
		mustEqual(t, p.Code.UserID, "u1")
		mustEqual(t, poll(t, s, "d1", ts(3*time.Second)).Outcome, store.PollInvalid)
	})

	t.Run("PollDeniedOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		_, err := s.DeviceCodes().Decide(ctx, "ten_a", "d1", store.DeviceDecision{Status: store.DeviceCodeDenied})
		mustNoErr(t, err)
		p := poll(t, s, "d1", ts(time.Second))
		mustEqual(t, p.Outcome, store.PollDenied)
		mustEqual(t, p.Code.Status, store.DeviceCodeConsumed)
		mustEqual(t, poll(t, s, "d1", ts(3*time.Second)).Outcome, store.PollInvalid)
	})

	t.Run("ConcurrentPollApproved", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.DeviceCodes().Create(ctx, newDeviceCode("ten_a", "d1", "u1")))
		approve(t, s, "ten_a", "d1")
		at := ts(time.Second)
		outcomes := make([]store.DevicePollOutcome, 10)
		errs := parallel(10, func(i int) error {
			p, err := s.DeviceCodes().Poll(ctx, "ten_a", "d1", at)
			outcomes[i] = p.Outcome
			return err
		})
		approved := 0
		for i, err := range errs {
			mustNoErr(t, err)
			if outcomes[i] == store.PollApproved {
				approved++
			}
		}
		mustEqual(t, approved, 1)
	})

	t.Run("PollExpired", func(t *testing.T) {
		s := open(t, newStore)
		d := newDeviceCode("ten_a", "d1", "u1")
		mustNoErr(t, s.DeviceCodes().Create(ctx, d))
		p := poll(t, s, "d1", d.ExpiresAt)
		mustEqual(t, p.Outcome, store.PollExpired)
		mustEqual(t, p.Code.ExpiredReportedAt.Equal(d.ExpiresAt), true)
		p = poll(t, s, "d1", d.ExpiresAt.Add(5*time.Second))
		mustEqual(t, p.Outcome, store.PollInvalid)
		mustEqual(t, p.Code.ExpiredReportedAt.Equal(d.ExpiresAt), true) // unchanged
	})

	t.Run("PollExpiredBeforeConsumption", func(t *testing.T) {
		s := open(t, newStore)
		d := newDeviceCode("ten_a", "d1", "u1")
		mustNoErr(t, s.DeviceCodes().Create(ctx, d))
		approve(t, s, "ten_a", "d1")
		p := poll(t, s, "d1", d.ExpiresAt)
		mustEqual(t, p.Outcome, store.PollExpired)
		mustEqual(t, p.Code.Status, store.DeviceCodeApproved) // not consumed
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		for i, c := range []struct {
			tenant string
			ttl    time.Duration
		}{{"ten_a", time.Minute}, {"ten_b", time.Minute}, {"ten_a", time.Hour}, {"ten_b", 2 * time.Minute}} {
			d := newDeviceCode(c.tenant, fmt.Sprintf("d%d", i), fmt.Sprintf("u%d", i))
			d.ExpiresAt = ts(c.ttl)
			mustNoErr(t, s.DeviceCodes().Create(ctx, d))
		}
		n, err := s.DeviceCodes().DeleteExpired(ctx, ts(2*time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 3)
		for i, want := range []bool{false, false, true, false} {
			tenant := []string{"ten_a", "ten_b", "ten_a", "ten_b"}[i]
			_, err := s.DeviceCodes().Get(ctx, tenant, fmt.Sprintf("d%d", i))
			ok, err := existsBy(err)
			mustNoErr(t, err)
			mustEqual(t, ok, want)
		}
	})

	t.Run("ConcurrentDeleteExpiredAndCreate", func(t *testing.T) {
		testSweepWhileCreating(t, newStore, deviceCodeSweepTarget())
	})
}

func deviceCodeSweepTarget() sweepTarget {
	ctx := context.Background()
	return sweepTarget{
		create: func(s store.Store, i int, expired bool) error {
			x := newDeviceCode("ten_a", fmt.Sprintf("d%d", i), fmt.Sprintf("u%d", i)) // expires at ts(10m)
			if expired {
				x.ExpiresAt = ts(10 * time.Second)
			}
			return s.DeviceCodes().Create(ctx, x)
		},
		exists: func(s store.Store, i int) (bool, error) {
			_, err := s.DeviceCodes().Get(ctx, "ten_a", fmt.Sprintf("d%d", i))
			return existsBy(err)
		},
		sweep:  func(s store.Store, c time.Time) (int, error) { return s.DeviceCodes().DeleteExpired(ctx, c) },
		cutoff: ts(time.Minute),
	}
}
