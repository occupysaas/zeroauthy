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

func newRefreshToken(tenantID, id, hash, family string) *store.RefreshToken {
	return &store.RefreshToken{
		TenantID: tenantID, ID: id, TokenHash: hash, FamilyID: family,
		ClientID: "spa", UserID: "auth0|u1", SessionID: "s1",
		Scopes: []string{"openid", "offline_access"}, Audience: "https://api.test",
		AuthTime: ts(0), Rotating: true,
		ExpiresAt: ts(30 * 24 * time.Hour), IdleExpiresAt: ts(15 * 24 * time.Hour), CreatedAt: ts(0),
	}
}

func getRT(t *testing.T, s store.Store, tenantID, hash string) *store.RefreshToken {
	t.Helper()
	rt, err := s.RefreshTokens().GetByTokenHash(context.Background(), tenantID, hash)
	mustNoErr(t, err)
	return rt
}

func testRefreshTokens(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CreateGet", func(t *testing.T) {
		s := open(t, newStore)
		want := newRefreshToken("ten_a", "rt1", "h1", "f1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, want))
		mustErrIs(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h2", "f1")), store.ErrConflict)
		mustErrIs(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt2", "h1", "f1")), store.ErrConflict)
		mustEqual(t, getRT(t, s, "ten_a", "h1"), want)
		_, err := s.RefreshTokens().GetByTokenHash(ctx, "ten_b", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "nope")
		mustErrIs(t, err, store.ErrNotFound)
		// The same ID and hash in another tenant is not a conflict.
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_b", "rt1", "h1", "f1")))
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newRefreshToken("ten_a", "rt1", "h1", "f1")
		mustNoErr(t, s.RefreshTokens().Create(ctx, in))
		in.Scopes[0] = "mutated"
		got := getRT(t, s, "ten_a", "h1")
		got.Scopes[1] = "mutated-too"
		mustEqual(t, getRT(t, s, "ten_a", "h1").Scopes, []string{"openid", "offline_access"})
	})

	t.Run("RotateAndReuse", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		next := newRefreshToken("ten_a", "rt2", "h2", "f1")
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", next, ts(time.Minute), 0))
		mustEqual(t, getRT(t, s, "ten_a", "h2"), next)
		old := getRT(t, s, "ten_a", "h1")
		mustEqual(t, old.RotatedAt != nil && old.RotatedAt.Equal(ts(time.Minute)), true)
		mustEqual(t, old.RevokedAt == nil, true)

		// Reuse: nothing is stored and the whole family is revoked.
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt3", "h3", "f1"), ts(2*time.Minute), 0)
		mustErrIs(t, err, store.ErrAlreadyUsed)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h3")
		mustErrIs(t, err, store.ErrNotFound)
		for _, h := range []string{"h1", "h2"} {
			rt := getRT(t, s, "ten_a", h)
			mustEqual(t, rt.RevokedAt != nil && rt.RevokedAt.Equal(ts(2*time.Minute)), true)
		}
		// A revoked token cannot be rotated.
		err = s.RefreshTokens().Rotate(ctx, "ten_a", "rt2", newRefreshToken("ten_a", "rt4", "h4", "f1"), ts(3*time.Minute), 0)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("RotateAfterFamilyRevoked", func(t *testing.T) {
		s := open(t, newStore)
		revokedAt := ts(2 * time.Minute)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h2", "f1"), ts(time.Minute), time.Hour))
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", revokedAt))
		// A rotated token of a revoked family is reuse, even inside the leeway.
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt3", "h3", "f1"), ts(3*time.Minute), time.Hour)
		mustErrIs(t, err, store.ErrAlreadyUsed)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h3")
		mustErrIs(t, err, store.ErrNotFound)
		rt1 := getRT(t, s, "ten_a", "h1")
		mustEqual(t, rt1.RevokedAt != nil && rt1.RevokedAt.Equal(revokedAt), true)
	})

	t.Run("RotateWithinLeeway", func(t *testing.T) {
		s := open(t, newStore)
		leeway := 30 * time.Second
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h2", "f1"), ts(time.Minute), leeway))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt3", "h3", "f1"), ts(time.Minute+10*time.Second), leeway))
		mustEqual(t, getRT(t, s, "ten_a", "h1").RotatedAt.Equal(ts(time.Minute)), true) // first rotation time kept
		mustEqual(t, getRT(t, s, "ten_a", "h2").RevokedAt == nil, true)
		mustEqual(t, getRT(t, s, "ten_a", "h3").RevokedAt == nil, true)
		// At exactly RotatedAt+leeway the window has closed.
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt4", "h4", "f1"), ts(time.Minute+leeway), leeway)
		mustErrIs(t, err, store.ErrAlreadyUsed)
		for _, h := range []string{"h1", "h2", "h3"} {
			mustEqual(t, getRT(t, s, "ten_a", h).RevokedAt != nil, true)
		}
	})

	t.Run("RotateUnknownAndConflict", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt9", "h9", "f9")))
		err := s.RefreshTokens().Rotate(ctx, "ten_a", "nope", newRefreshToken("ten_a", "rt2", "h2", "f1"), ts(0), 0)
		mustErrIs(t, err, store.ErrNotFound)
		err = s.RefreshTokens().Rotate(ctx, "ten_b", "rt1", newRefreshToken("ten_b", "rt2", "h2", "f1"), ts(0), 0)
		mustErrIs(t, err, store.ErrNotFound)
		// A successor whose hash exists changes nothing.
		err = s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h9", "f1"), ts(0), 0)
		mustErrIs(t, err, store.ErrConflict)
		mustEqual(t, getRT(t, s, "ten_a", "h1").RotatedAt == nil, true)
		// A successor from another family is refused.
		err = s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", newRefreshToken("ten_a", "rt2", "h2", "f2"), ts(0), 0)
		mustErrIs(t, err, store.ErrConflict)
		mustEqual(t, getRT(t, s, "ten_a", "h1").RotatedAt == nil, true)
	})

	t.Run("ConcurrentRotate", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		const n = 10
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				next := newRefreshToken("ten_a", fmt.Sprintf("next%d", i), fmt.Sprintf("hn%d", i), "f1")
				errs[i] = s.RefreshTokens().Rotate(ctx, "ten_a", "rt1", next, ts(time.Minute), 0)
			}()
		}
		wg.Wait()
		ok, reused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAlreadyUsed):
				reused++
			default:
				t.Fatalf("unexpected error %v", err)
			}
		}
		mustEqual(t, ok, 1)
		mustEqual(t, reused, n-1)
		// The race was reuse, so even the winning successor is revoked, and
		// only the winner's successor was stored.
		stored := 0
		for i := range n {
			rt, err := s.RefreshTokens().GetByTokenHash(ctx, "ten_a", fmt.Sprintf("hn%d", i))
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			mustNoErr(t, err)
			stored++
			mustEqual(t, rt.RevokedAt != nil, true)
		}
		mustEqual(t, stored, 1)
	})

	t.Run("Touch", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt1", "h1", "f1")))
		mustNoErr(t, s.RefreshTokens().Touch(ctx, "ten_a", "rt1", ts(20*24*time.Hour)))
		mustEqual(t, getRT(t, s, "ten_a", "h1").IdleExpiresAt, ts(20*24*time.Hour))
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_a", "nope", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_b", "rt1", ts(0)), store.ErrNotFound)
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", ts(time.Minute)))
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_a", "rt1", ts(0)), store.ErrNotFound)

		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "rt2", "h2", "f2")))
		mustNoErr(t, s.RefreshTokens().Rotate(ctx, "ten_a", "rt2", newRefreshToken("ten_a", "rt3", "h3", "f2"), ts(time.Minute), 0))
		mustErrIs(t, s.RefreshTokens().Touch(ctx, "ten_a", "rt2", ts(0)), store.ErrNotFound) // rotated
	})

	t.Run("RevokeFamily", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "a1", "ha1", "f1")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "a2", "ha2", "f1")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_a", "b1", "hb1", "f2")))
		mustNoErr(t, s.RefreshTokens().Create(ctx, newRefreshToken("ten_b", "c1", "hc1", "f1")))
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", ts(5*time.Minute)))
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "f1", ts(9*time.Minute))) // keeps the first time
		mustNoErr(t, s.RefreshTokens().RevokeFamily(ctx, "ten_a", "unknown", ts(0)))
		for _, h := range []string{"ha1", "ha2"} {
			rt := getRT(t, s, "ten_a", h)
			mustEqual(t, rt.RevokedAt != nil && rt.RevokedAt.Equal(ts(5*time.Minute)), true)
		}
		mustEqual(t, getRT(t, s, "ten_a", "hb1").RevokedAt == nil, true)
		mustEqual(t, getRT(t, s, "ten_b", "hc1").RevokedAt == nil, true)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		live := newRefreshToken("ten_a", "live", "h-live", "f1")
		absolute := newRefreshToken("ten_a", "abs", "h-abs", "f2")
		absolute.ExpiresAt = ts(time.Hour)
		idle := newRefreshToken("ten_b", "idle", "h-idle", "f3")
		idle.IdleExpiresAt = ts(time.Hour)
		forever := newRefreshToken("ten_a", "forever", "h-forever", "f4")
		forever.ExpiresAt, forever.IdleExpiresAt = time.Time{}, time.Time{}
		for _, x := range []*store.RefreshToken{live, absolute, idle, forever} {
			mustNoErr(t, s.RefreshTokens().Create(ctx, x))
		}
		n, err := s.RefreshTokens().DeleteExpired(ctx, ts(2*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		getRT(t, s, "ten_a", "h-live")
		getRT(t, s, "ten_a", "h-forever")
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h-abs")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_b", "h-idle")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
