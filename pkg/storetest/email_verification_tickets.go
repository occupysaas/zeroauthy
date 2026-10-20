package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newVerificationTicket(tenantID, id, hash string) *store.EmailVerificationTicket {
	return &store.EmailVerificationTicket{
		TenantID: tenantID, ID: id, TokenHash: hash, UserID: "auth0|u1", Connection: "Database",
		ClientID: "spa", Lang: "fr", Email: "alice@example.test",
		ResultURL: "https://app.test/verified", IncludeEmailInRedirect: true, ExpiresAt: ts(24 * time.Hour), CreatedAt: ts(0),
	}
}

func testEmailVerificationTickets(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetConsume", func(t *testing.T) {
		s := open(t, newStore)
		want := newVerificationTicket("ten_a", "pr1", "h1")
		mustNoErr(t, s.EmailVerificationTickets().Create(ctx, want))
		mustErrIs(t, s.EmailVerificationTickets().Create(ctx, newVerificationTicket("ten_a", "pr1", "h2")), store.ErrConflict)
		mustErrIs(t, s.EmailVerificationTickets().Create(ctx, newVerificationTicket("ten_a", "pr2", "h1")), store.ErrConflict)
		got, err := s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)

		used, err := s.EmailVerificationTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, used.UsedAt != nil && used.UsedAt.Equal(ts(time.Minute)), true)
		again, err := s.EmailVerificationTickets().Consume(ctx, "ten_a", "h1", ts(2*time.Minute))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(ts(time.Minute)), true)
		_, err = s.EmailVerificationTickets().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.EmailVerificationTickets().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
	})

	// The verification page uses the ticket and sets email_verified in one
	// transaction: a failure after Consume leaves the ticket usable.
	t.Run("ConsumeRollsBackWithTx", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.EmailVerificationTickets().Create(ctx, newVerificationTicket("ten_a", "pr1", "h1")))
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.EmailVerificationTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute)); err != nil {
				return err
			}
			return boom
		})
		mustErrIs(t, err, boom)
		got, err := s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.UsedAt == nil, true)
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.EmailVerificationTickets().Create(ctx, newVerificationTicket("ten_a", "pr1", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.EmailVerificationTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
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

	t.Run("DeleteByUser", func(t *testing.T) {
		s := open(t, newStore)
		mine1 := newVerificationTicket("ten_a", "pr1", "h1")
		mine2 := newVerificationTicket("ten_a", "pr2", "h2")
		other := newVerificationTicket("ten_a", "pr3", "h3")
		other.UserID = "auth0|u2"
		used := newVerificationTicket("ten_a", "pr4", "h4")
		foreign := newVerificationTicket("ten_b", "pr1", "h1") // same user ID in another tenant
		for _, tk := range []*store.EmailVerificationTicket{mine1, mine2, other, used, foreign} {
			mustNoErr(t, s.EmailVerificationTickets().Create(ctx, tk))
		}
		_, err := s.EmailVerificationTickets().Consume(ctx, "ten_a", "h4", ts(time.Minute))
		mustNoErr(t, err)
		n, err := s.EmailVerificationTickets().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		for _, h := range []string{"h1", "h2"} {
			_, err = s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", h)
			mustErrIs(t, err, store.ErrNotFound)
		}
		_, err = s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", "h3")
		mustNoErr(t, err)
		// A used ticket is kept, so a replayed link can still be reported
		// as used until DeleteExpired removes it.
		got, err := s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", "h4")
		mustNoErr(t, err)
		mustEqual(t, got.UsedAt != nil, true)
		_, err = s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_b", "h1")
		mustNoErr(t, err)
		n, err = s.EmailVerificationTickets().DeleteByUser(ctx, "ten_a", "auth0|nobody")
		mustNoErr(t, err)
		mustEqual(t, n, 0)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		for i, exp := range []time.Duration{time.Hour, 48 * time.Hour} {
			tk := newVerificationTicket("ten_a", fmt.Sprintf("pr%d", i), fmt.Sprintf("h%d", i))
			tk.ExpiresAt = ts(exp)
			mustNoErr(t, s.EmailVerificationTickets().Create(ctx, tk))
		}
		n, err := s.EmailVerificationTickets().DeleteExpired(ctx, ts(24*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.EmailVerificationTickets().Create(ctx, newVerificationTicket("ten_a", "pr1", "h1")))
		used, err := s.EmailVerificationTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
		mustNoErr(t, err)
		*used.UsedAt = ts(time.Hour)

		got, err := s.EmailVerificationTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.UsedAt != nil && got.UsedAt.Equal(ts(time.Minute)), true)
	})
}
