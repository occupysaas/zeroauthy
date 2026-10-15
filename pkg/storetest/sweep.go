package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// sweepTarget adapts one repository with DeleteExpired to the
// sweeper-versus-insert case.
type sweepTarget struct {
	// create inserts row i, already expired at cutoff or not.
	create func(s store.Store, i int, expired bool) error
	// exists reports whether row i is still stored.
	exists func(s store.Store, i int) (bool, error)
	sweep  func(s store.Store, cutoff time.Time) (int, error)
	cutoff time.Time
}

// testSweepWhileCreating runs DeleteExpired concurrently with Create: every
// Create must succeed, and the sweepers together must delete exactly the
// expired rows, never a live one (a range DELETE must not deadlock with, or
// swallow, rows inserted beside it).
func testSweepWhileCreating(t *testing.T, newStore Factory, tg sweepTarget) {
	const (
		seeded   = 8  // rows present before the race
		creators = 16 // rows created during the race
		sweepers = 4
	)
	s := open(t, newStore)
	expired := func(i int) bool { return i%2 == 0 }
	for i := range seeded {
		mustNoErr(t, tg.create(s, i, expired(i)))
	}
	counts := make([]int, sweepers)
	errs := parallel(sweepers+creators, func(i int) error {
		if i < sweepers {
			n, err := tg.sweep(s, tg.cutoff)
			counts[i] = n
			return err
		}
		row := seeded + i - sweepers
		return tg.create(s, row, expired(row))
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	n, err := tg.sweep(s, tg.cutoff)
	mustNoErr(t, err)
	deleted := n
	for _, c := range counts {
		deleted += c
	}
	total := seeded + creators
	mustEqual(t, deleted, total/2)
	for i := range total {
		ok, err := tg.exists(s, i)
		mustNoErr(t, err)
		if ok == expired(i) {
			t.Errorf("row %d (expired %v): stored = %v", i, expired(i), ok)
		}
	}
}

// existsBy turns a store lookup into a sweepTarget.exists result.
func existsBy(err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

func sessionSweepTarget() sweepTarget {
	ctx := context.Background()
	return sweepTarget{
		create: func(s store.Store, i int, expired bool) error {
			x := newSession("ten_a", fmt.Sprintf("s%d", i), fmt.Sprintf("h%d", i))
			if expired {
				x.IdleExpiresAt = ts(time.Hour)
			}
			return s.Sessions().Create(ctx, x)
		},
		exists: func(s store.Store, i int) (bool, error) {
			_, err := s.Sessions().GetByTokenHash(ctx, "ten_a", fmt.Sprintf("h%d", i))
			return existsBy(err)
		},
		sweep:  func(s store.Store, c time.Time) (int, error) { return s.Sessions().DeleteExpired(ctx, c) },
		cutoff: ts(2 * time.Hour),
	}
}

func refreshTokenSweepTarget() sweepTarget {
	ctx := context.Background()
	return sweepTarget{
		create: func(s store.Store, i int, expired bool) error {
			x := newRefreshToken("ten_a", fmt.Sprintf("rt%d", i), fmt.Sprintf("h%d", i), fmt.Sprintf("f%d", i))
			if expired {
				x.ExpiresAt = ts(time.Hour)
			}
			return s.RefreshTokens().Create(ctx, x)
		},
		exists: func(s store.Store, i int) (bool, error) {
			_, err := s.RefreshTokens().GetByTokenHash(ctx, "ten_a", fmt.Sprintf("h%d", i))
			return existsBy(err)
		},
		sweep:  func(s store.Store, c time.Time) (int, error) { return s.RefreshTokens().DeleteExpired(ctx, c) },
		cutoff: ts(2 * time.Hour),
	}
}

func authCodeSweepTarget() sweepTarget {
	ctx := context.Background()
	return sweepTarget{
		create: func(s store.Store, i int, expired bool) error {
			x := newAuthCode("ten_a", fmt.Sprintf("h%d", i)) // expires at ts(1m)
			if expired {
				x.ExpiresAt = ts(10 * time.Second)
			}
			return s.AuthCodes().Create(ctx, x)
		},
		exists: func(s store.Store, i int) (bool, error) {
			_, err := s.AuthCodes().Get(ctx, "ten_a", fmt.Sprintf("h%d", i))
			return existsBy(err)
		},
		sweep:  func(s store.Store, c time.Time) (int, error) { return s.AuthCodes().DeleteExpired(ctx, c) },
		cutoff: ts(30 * time.Second),
	}
}
