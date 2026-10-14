package storetest

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newSession(tenantID, id, tokenHash string) *store.LoginSession {
	return &store.LoginSession{
		TenantID: tenantID, ID: id, TokenHash: tokenHash,
		UserID: "auth0|u1", Connection: "Database",
		AuthenticatedAt: ts(0), ClientIDs: []string{"spa"},
		ExpiresAt: ts(7 * 24 * time.Hour), IdleExpiresAt: ts(3 * 24 * time.Hour), CreatedAt: ts(0),
	}
}

func testSessions(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newSession("ten_a", "s1", "hash1")
		mustNoErr(t, s.Sessions().Create(ctx, want))
		mustErrIs(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash2")), store.ErrConflict)
		mustErrIs(t, s.Sessions().Create(ctx, newSession("ten_a", "s2", "hash1")), store.ErrConflict)

		got, err := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustNoErr(t, err)
		mustEqual(t, got, want)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_b", "hash1")
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, s.Sessions().Touch(ctx, "ten_a", "s1", ts(4*24*time.Hour)))
		mustNoErr(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "web"))
		mustNoErr(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "web")) // idempotent
		want.ClientIDs = []string{"spa", "web"}
		want.IdleExpiresAt = ts(4 * 24 * time.Hour)
		got, _ = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, got, want)
		mustErrIs(t, s.Sessions().Touch(ctx, "ten_b", "s1", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Sessions().AddClient(ctx, "ten_b", "s1", "x"), store.ErrNotFound)

		mustNoErr(t, s.Sessions().Delete(ctx, "ten_a", "s1"))
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Sessions().Delete(ctx, "ten_a", "s1"), store.ErrNotFound)
		mustErrIs(t, s.Sessions().Touch(ctx, "ten_a", "s1", ts(0)), store.ErrNotFound)
		mustErrIs(t, s.Sessions().AddClient(ctx, "ten_a", "s1", "x"), store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newSession("ten_a", "s1", "hash1")
		mustNoErr(t, s.Sessions().Create(ctx, in))
		in.ClientIDs[0] = "mutated"
		got, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		got.ClientIDs[0] = "mutated-too"
		again, _ := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, again.ClientIDs, []string{"spa"})
	})

	t.Run("ConcurrentAddClient", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "hash1")))
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = s.Sessions().AddClient(ctx, "ten_a", "s1", fmt.Sprintf("c%d", i))
			}()
		}
		wg.Wait()
		got, err := s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustNoErr(t, err)
		mustEqual(t, len(got.ClientIDs), 21) // "spa" plus 20 distinct clients
		for i := range 20 {
			mustEqual(t, slices.Contains(got.ClientIDs, fmt.Sprintf("c%d", i)), true)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		live := newSession("ten_a", "live", "h-live")
		absolute := newSession("ten_a", "abs", "h-abs")
		absolute.ExpiresAt = ts(time.Hour)
		idle := newSession("ten_a", "idle", "h-idle")
		idle.IdleExpiresAt = ts(time.Hour)
		edge := newSession("ten_a", "edge", "h-edge")
		edge.IdleExpiresAt = ts(2 * time.Hour) // exactly at the cutoff: expired
		other := newSession("ten_b", "other", "h-other")
		other.IdleExpiresAt = ts(time.Hour)
		for _, x := range []*store.LoginSession{live, absolute, idle, edge, other} {
			mustNoErr(t, s.Sessions().Create(ctx, x))
		}
		n, err := s.Sessions().DeleteExpired(ctx, ts(2*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 4)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h-live")
		mustNoErr(t, err)
		for _, k := range [][2]string{{"ten_a", "h-abs"}, {"ten_a", "h-idle"}, {"ten_a", "h-edge"}, {"ten_b", "h-other"}} {
			_, err = s.Sessions().GetByTokenHash(ctx, k[0], k[1])
			mustErrIs(t, err, store.ErrNotFound)
		}
	})

	t.Run("DeleteByUser", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s1", "h1"))) // auth0|u1
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_a", "s2", "h2"))) // auth0|u1
		other := newSession("ten_a", "s3", "h3")
		other.UserID = "auth0|u2"
		mustNoErr(t, s.Sessions().Create(ctx, other))
		mustNoErr(t, s.Sessions().Create(ctx, newSession("ten_b", "s4", "h4"))) // same user ID, other tenant
		n, err := s.Sessions().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "h3")
		mustNoErr(t, err)
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_b", "h4")
		mustNoErr(t, err)
	})
}
