package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newAuthCode(tenantID, hash string) *store.AuthCode {
	return &store.AuthCode{
		TenantID: tenantID, CodeHash: hash, ClientID: "spa", RedirectURI: "https://app.test/cb",
		UserID: "auth0|u1", SessionID: "s1", Scopes: []string{"openid", "email"},
		Audience: "https://api.test", Nonce: "n", CodeChallenge: "ch", CodeChallengeMethod: "S256",
		AuthTime: ts(0), ExpiresAt: ts(time.Minute), CreatedAt: ts(0),
	}
}

func testAuthCodes(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("ConsumeOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		mustErrIs(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")), store.ErrConflict)

		got, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustNoErr(t, err)
		want := newAuthCode("ten_a", "h1")
		used := ts(10 * time.Second)
		want.UsedAt = &used
		mustEqual(t, got, want)

		again, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(20*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(used), true) // the first use time is kept
		mustEqual(t, again.ClientID, "spa")
	})

	t.Run("ReplayRecorded", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		first, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustNoErr(t, err)
		mustEqual(t, first.ReplayedAt == nil, true)

		replay, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(20*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, replay.ReplayedAt != nil && replay.ReplayedAt.Equal(ts(20*time.Second)), true)

		// A later replay keeps the first replay time.
		again, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(30*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.ReplayedAt != nil && again.ReplayedAt.Equal(ts(20*time.Second)), true)
		mustEqual(t, again.UsedAt.Equal(ts(10*time.Second)), true)

		got, err := s.AuthCodes().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.ReplayedAt != nil && got.ReplayedAt.Equal(ts(20*time.Second)), true)
	})

	t.Run("Get", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		got, err := s.AuthCodes().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, newAuthCode("ten_a", "h1"))
		_, err = s.AuthCodes().Get(ctx, "ten_a", "nope")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthCodes().Get(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("GetReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		_, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustNoErr(t, err)
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(20*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		got, err := s.AuthCodes().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.UsedAt != nil && got.ReplayedAt != nil, true)
		got.Scopes[0] = "mutated"
		*got.UsedAt = ts(time.Hour)
		*got.ReplayedAt = ts(time.Hour)
		again, err := s.AuthCodes().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, again.Scopes, []string{"openid", "email"})
		mustEqual(t, again.UsedAt.Equal(ts(10*time.Second)), true)
		mustEqual(t, again.ReplayedAt.Equal(ts(20*time.Second)), true)
	})

	t.Run("UnknownAndOtherTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		_, err := s.AuthCodes().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthCodes().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		// The failed cross-tenant attempt must not have consumed it.
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(0))
		mustNoErr(t, err)
	})

	t.Run("ConcurrentDeleteExpiredAndCreate", func(t *testing.T) {
		testSweepWhileCreating(t, newStore, authCodeSweepTarget())
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		short := newAuthCode("ten_a", "h1") // expires ts(1m)
		long := newAuthCode("ten_a", "h2")
		long.ExpiresAt = ts(time.Hour)
		mustNoErr(t, s.AuthCodes().Create(ctx, short))
		mustNoErr(t, s.AuthCodes().Create(ctx, long))
		n, err := s.AuthCodes().DeleteExpired(ctx, ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h2", ts(0))
		mustNoErr(t, err)
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(time.Second))
			}()
		}
		wg.Wait()
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
		got, err := s.AuthCodes().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.ReplayedAt != nil, true)
	})
}
