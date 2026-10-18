package storetest

import (
	"context"
	"fmt"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testPasswordHistories(t *testing.T, newStore Factory) {
	ctx := context.Background()
	hashes := func(t *testing.T, s store.Store, tenant, user string) []string {
		t.Helper()
		got, err := s.PasswordHistories().List(ctx, tenant, user)
		mustNoErr(t, err)
		out := []string{}
		for _, h := range got {
			out = append(out, string(h))
		}
		return out
	}

	t.Run("AddListNewestFirst", func(t *testing.T) {
		s := open(t, newStore)
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{})
		for _, h := range []string{"h1", "h2", "h3"} {
			mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte(h), 5))
		}
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{"h3", "h2", "h1"})
	})

	t.Run("TrimsToNewestKeep", func(t *testing.T) {
		s := open(t, newStore)
		for _, h := range []string{"h1", "h2", "h3", "h4"} {
			mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte(h), 2))
		}
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{"h4", "h3"})
		// A smaller keep trims what is already stored; a larger one keeps it.
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("h5"), 10))
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{"h5", "h4", "h3"})
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("h6"), 1))
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{"h6"})
	})

	t.Run("NonPositiveKeepStoresNothing", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("h1"), 3))
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("h2"), 0))
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{})
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("h3"), -1))
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{})
	})

	t.Run("DuplicateHashesAreKept", func(t *testing.T) {
		s := open(t, newStore)
		for range 2 {
			mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("same"), 5))
		}
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{"same", "same"})
	})

	t.Run("IsolatedPerUserAndTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", []byte("a1"), 5))
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u2", []byte("a2"), 1))
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_b", "auth0|u1", []byte("b1"), 5))
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u2", []byte("a3"), 1))
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u1"), []string{"a1"})
		mustEqual(t, hashes(t, s, "ten_a", "auth0|u2"), []string{"a3"})
		mustEqual(t, hashes(t, s, "ten_b", "auth0|u1"), []string{"b1"})
	})

	t.Run("BinaryHashIsCopied", func(t *testing.T) {
		s := open(t, newStore)
		in := []byte{0, 1, 0xff, 0}
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", in, 3))
		in[0] = 9
		got, err := s.PasswordHistories().List(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, got, [][]byte{{0, 1, 0xff, 0}})
		got[0][1] = 9
		again, _ := s.PasswordHistories().List(ctx, "ten_a", "auth0|u1")
		mustEqual(t, again, [][]byte{{0, 1, 0xff, 0}})
	})

	t.Run("ConcurrentAdds", func(t *testing.T) {
		s := open(t, newStore)
		for i, err := range parallel(8, func(i int) error {
			return s.PasswordHistories().Add(ctx, "ten_a", "auth0|u1", fmt.Appendf(nil, "h%d", i), 100)
		}) {
			if err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}
		mustEqual(t, len(hashes(t, s, "ten_a", "auth0|u1")), 8)
	})

	t.Run("DeletedWithTenant", func(t *testing.T) {
		s := open(t, newStore)
		tn := newTenant("a")
		mustNoErr(t, s.Tenants().Create(ctx, tn))
		mustNoErr(t, s.PasswordHistories().Add(ctx, tn.ID, "auth0|u1", []byte("h1"), 3))
		mustNoErr(t, s.PasswordHistories().Add(ctx, "ten_other", "auth0|u1", []byte("h2"), 3))
		mustNoErr(t, s.Tenants().Delete(ctx, tn.ID))
		mustEqual(t, hashes(t, s, tn.ID, "auth0|u1"), []string{})
		mustEqual(t, hashes(t, s, "ten_other", "auth0|u1"), []string{"h2"})
	})
}
