package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newAuthTransaction(tenantID, id string) *store.AuthTransaction {
	return &store.AuthTransaction{
		TenantID: tenantID, ID: id, CookieHash: "cookie-" + id, CSRFToken: "csrf-" + id, ClientID: "spa",
		Params:    map[string]string{"redirect_uri": "https://app.test/cb", "state": "xyz"},
		ExpiresAt: ts(15 * time.Minute), CreatedAt: ts(0),
	}
}

func testAuthTransactions(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGetDelete", func(t *testing.T) {
		s := open(t, newStore)
		want := newAuthTransaction("ten_a", "t1")
		mustNoErr(t, s.AuthTransactions().Create(ctx, want))
		mustErrIs(t, s.AuthTransactions().Create(ctx, newAuthTransaction("ten_a", "t1")), store.ErrConflict)
		got, err := s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.AuthTransactions().Get(ctx, "ten_b", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, s.AuthTransactions().Delete(ctx, "ten_a", "t1"))
		_, err = s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.AuthTransactions().Delete(ctx, "ten_a", "t1"), store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newAuthTransaction("ten_a", "t1")
		mustNoErr(t, s.AuthTransactions().Create(ctx, in))
		in.Params["state"] = "mutated"
		got, _ := s.AuthTransactions().Get(ctx, "ten_a", "t1")
		got.Params["redirect_uri"] = "https://evil.test"
		again, _ := s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustEqual(t, again.Params, map[string]string{"redirect_uri": "https://app.test/cb", "state": "xyz"})
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		early := newAuthTransaction("ten_a", "t1") // expires ts(15m)
		late := newAuthTransaction("ten_a", "t2")
		late.ExpiresAt = ts(time.Hour)
		other := newAuthTransaction("ten_b", "t3")
		other.ExpiresAt = ts(time.Minute)
		for _, x := range []*store.AuthTransaction{early, late, other} {
			mustNoErr(t, s.AuthTransactions().Create(ctx, x))
		}
		n, err := s.AuthTransactions().DeleteExpired(ctx, ts(15*time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		_, err = s.AuthTransactions().Get(ctx, "ten_a", "t2")
		mustNoErr(t, err)
		_, err = s.AuthTransactions().Get(ctx, "ten_a", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthTransactions().Get(ctx, "ten_b", "t3")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
