package storetest

import (
	"context"
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

		want.ClientIDs = append(want.ClientIDs, "web")
		want.IdleExpiresAt = ts(4 * 24 * time.Hour)
		mustNoErr(t, s.Sessions().Update(ctx, want))
		got, _ = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustEqual(t, got, want)

		mustNoErr(t, s.Sessions().Delete(ctx, "ten_a", "s1"))
		_, err = s.Sessions().GetByTokenHash(ctx, "ten_a", "hash1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Sessions().Delete(ctx, "ten_a", "s1"), store.ErrNotFound)
		mustErrIs(t, s.Sessions().Update(ctx, want), store.ErrNotFound)
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
}
