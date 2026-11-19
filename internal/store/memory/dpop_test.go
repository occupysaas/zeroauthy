package memory_test

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// A sweep consumes the earliest deadline in the expiry index, one claim per
// call. Reclaim it at the original clock time to distinguish removal from
// ordinary expiry, then keep it live beyond this sweep's cutoff.
func TestDPoPPurgeExpiryOrder(t *testing.T) {
	repo := memory.New().DPoP()
	ctx := t.Context()
	start := time.Unix(1000, 0)
	const claims = 32
	cutoff := start.Add(claims * time.Second)
	for i := claims; i > 0; i-- {
		if err := repo.UseProof(ctx, "tenant", "https://tenant.test", "key", strconv.Itoa(i), start, start.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= claims; i++ {
		n, err := repo.PurgeBefore(ctx, cutoff, 1)
		if n != 1 || err != nil {
			t.Fatalf("purge %d = (%d, %v)", i, n, err)
		}
		if err := repo.UseProof(ctx, "tenant", "https://tenant.test", "key", strconv.Itoa(i), start, cutoff.Add(time.Minute)); err != nil {
			t.Fatalf("earliest deadline %d was not removed: %v", i, err)
		}
	}
	n, err := repo.PurgeBefore(ctx, cutoff, 1)
	if n != 0 || err != nil {
		t.Fatalf("live claims purge = (%d, %v)", n, err)
	}
}

// Replacing and deleting claims in a rolled-back transaction must restore
// both their original replay decisions and the deadlines used by the sweeper.
func TestDPoPClaimLifecycle(t *testing.T) {
	s := memory.New()
	ctx := t.Context()
	start := time.Unix(1000, 0)
	first := start.Add(time.Minute)
	later := first.Add(time.Minute)
	use := func(s store.Store, tenant string, at, expiry time.Time) error {
		return s.DPoP().UseProof(ctx, tenant, "https://tenant.test", "key", "jti", at, expiry)
	}
	for _, tid := range []string{"a", "b"} {
		if err := s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}); err != nil {
			t.Fatal(err)
		}
		if err := use(s, tid, start, first); err != nil {
			t.Fatal(err)
		}
	}
	rollback := errors.New("rollback")
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := use(tx, "a", first, later); err != nil {
			return err
		}
		if err := tx.Tenants().Delete(ctx, "b"); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if err := use(s, "b", start, first); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("rolled-back deletion: %v", err)
	}
	if err := use(s, "a", first, later); err != nil {
		t.Fatalf("rolled-back replacement: %v", err)
	}
	if err := s.Tenants().Delete(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	n, err := s.DPoP().PurgeBefore(ctx, first, 1)
	if n != 0 || err != nil {
		t.Fatalf("purged obsolete deadline: (%d,%v)", n, err)
	}
	if err := use(s, "a", first, later); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("replacement not retained: %v", err)
	}
	n, err = s.DPoP().PurgeBefore(ctx, later, 1)
	if n != 1 || err != nil {
		t.Fatalf("replacement deadline: (%d,%v)", n, err)
	}
}
