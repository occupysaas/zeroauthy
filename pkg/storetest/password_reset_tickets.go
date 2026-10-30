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

func newTicket(tenantID, id, hash string) *store.PasswordResetTicket {
	return &store.PasswordResetTicket{
		TenantID: tenantID, ID: id, TokenHash: hash, UserID: "auth0|u1", Connection: "Database",
		ClientID: "spa", Lang: "fr",
		ResultURL: "https://app.test/reset", IncludeEmailInRedirect: true, MarkEmailVerified: true, ExpiresAt: ts(24 * time.Hour), CreatedAt: ts(0),
	}
}

func testPasswordResetTickets(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetConsume", func(t *testing.T) {
		s := open(t, newStore)
		want := newTicket("ten_a", "pr1", "h1")
		want.OrganizationID = "org_0000000000000014"
		mustNoErr(t, s.PasswordResetTickets().Create(ctx, want))
		mustErrIs(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr1", "h2")), store.ErrConflict)
		mustErrIs(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr2", "h1")), store.ErrConflict)
		got, err := s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)

		used, err := s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, used.OrganizationID, want.OrganizationID)
		mustEqual(t, used.UsedAt != nil && used.UsedAt.Equal(ts(time.Minute)), true)
		again, err := s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(2*time.Minute))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(ts(time.Minute)), true)
		_, err = s.PasswordResetTickets().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.PasswordResetTickets().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ConcurrentConsume", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr1", "h1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
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
		mine1 := newTicket("ten_a", "pr1", "h1")
		mine2 := newTicket("ten_a", "pr2", "h2")
		other := newTicket("ten_a", "pr3", "h3")
		other.UserID = "auth0|u2"
		used := newTicket("ten_a", "pr4", "h4")
		foreign := newTicket("ten_b", "pr1", "h1") // same user ID in another tenant
		for _, tk := range []*store.PasswordResetTicket{mine1, mine2, other, used, foreign} {
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, tk))
		}
		_, err := s.PasswordResetTickets().Consume(ctx, "ten_a", "h4", ts(time.Minute))
		mustNoErr(t, err)
		n, err := s.PasswordResetTickets().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		for _, h := range []string{"h1", "h2"} {
			_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", h)
			mustErrIs(t, err, store.ErrNotFound)
		}
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h3")
		mustNoErr(t, err)
		// A used ticket is kept, so a replayed link can still be reported
		// as used until DeleteExpired removes it.
		got, err := s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h4")
		mustNoErr(t, err)
		mustEqual(t, got.UsedAt != nil, true)
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_b", "h1")
		mustNoErr(t, err)
		n, err = s.PasswordResetTickets().DeleteByUser(ctx, "ten_a", "auth0|nobody")
		mustNoErr(t, err)
		mustEqual(t, n, 0)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		for i, exp := range []time.Duration{time.Hour, 48 * time.Hour} {
			tk := newTicket("ten_a", fmt.Sprintf("pr%d", i), fmt.Sprintf("h%d", i))
			tk.ExpiresAt = ts(exp)
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, tk))
		}
		n, err := s.PasswordResetTickets().DeleteExpired(ctx, ts(24*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PasswordResetTickets().Create(ctx, newTicket("ten_a", "pr1", "h1")))
		used, err := s.PasswordResetTickets().Consume(ctx, "ten_a", "h1", ts(time.Minute))
		mustNoErr(t, err)
		*used.UsedAt = ts(time.Hour)

		got, err := s.PasswordResetTickets().GetByTokenHash(ctx, "ten_a", "h1")
		mustNoErr(t, err)
		mustEqual(t, got.UsedAt != nil && got.UsedAt.Equal(ts(time.Minute)), true)
	})
}
