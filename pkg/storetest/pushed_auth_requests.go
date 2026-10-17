package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newPushedAuthRequest(tenantID, hash string) *store.PushedAuthRequest {
	return &store.PushedAuthRequest{
		TenantID: tenantID, IDHash: hash, ClientID: "web",
		Params: map[string]string{
			"client_id": "web", "redirect_uri": "https://web.test/cb", "response_type": "code",
			"scope": "openid", "state": "s1", "ext-tenant_hint": "blue",
		},
		ExpiresAt: ts(30 * time.Second), CreatedAt: ts(0),
	}
}

func testPushedAuthRequests(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("ConsumeOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		mustErrIs(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")), store.ErrConflict)

		got, err := s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(5*time.Second))
		mustNoErr(t, err)
		want := newPushedAuthRequest("ten_a", "h1")
		used := ts(5 * time.Second)
		want.UsedAt = &used
		mustEqual(t, got, want)

		again, err := s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(used), true) // the first use time is kept
		mustEqual(t, again.ClientID, "web")
	})

	t.Run("GetReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		got, err := s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, newPushedAuthRequest("ten_a", "h1"))
		got.Params["state"] = "mutated"
		again, err := s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, again.Params["state"], "s1")
	})

	t.Run("CreateCopiesInput", func(t *testing.T) {
		s := open(t, newStore)
		in := newPushedAuthRequest("ten_a", "h1")
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, in))
		in.Params["state"] = "mutated"
		got, err := s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.Params["state"], "s1")
	})

	t.Run("UnknownAndOtherTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		_, err := s.PushedAuthRequests().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PushedAuthRequests().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PushedAuthRequests().Get(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		// The failed cross-tenant attempt must not have consumed it.
		_, err = s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(0))
		mustNoErr(t, err)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		short := newPushedAuthRequest("ten_a", "h1") // expires ts(30s)
		long := newPushedAuthRequest("ten_b", "h2")
		long.ExpiresAt = ts(time.Hour)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, short))
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, long))
		_, err := s.PushedAuthRequests().Consume(ctx, "ten_b", "h2", ts(time.Second)) // used rows are swept by expiry too
		mustNoErr(t, err)
		n, err := s.PushedAuthRequests().DeleteExpired(ctx, ts(30*time.Second))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.PushedAuthRequests().Get(ctx, "ten_a", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PushedAuthRequests().Get(ctx, "ten_b", "h2")
		mustNoErr(t, err)
	})

	t.Run("ConcurrentDeleteExpiredAndCreate", func(t *testing.T) {
		testSweepWhileCreating(t, newStore, pushedAuthRequestSweepTarget())
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, newPushedAuthRequest("ten_a", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.PushedAuthRequests().Consume(ctx, "ten_a", "h1", ts(time.Second))
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
	})
}
