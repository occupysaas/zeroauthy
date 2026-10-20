package storetest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newUserGrant(tenantID, id, clientID, userID, audience string, scopes ...string) *store.UserGrant {
	return &store.UserGrant{
		TenantID: tenantID, ID: id, ClientID: clientID, UserID: userID, Audience: audience,
		Scopes: scopes, CreatedAt: ts(0), UpdatedAt: ts(0),
	}
}

func testUserGrants(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("UpsertFindDelete", func(t *testing.T) {
		s := open(t, newStore)
		in := newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read:things")
		got, err := s.UserGrants().Upsert(ctx, in)
		mustNoErr(t, err)
		mustEqual(t, got, in)
		found, err := s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, found, in)

		// Same key, new ID and scopes: the first ID and CreatedAt are kept.
		again := newUserGrant("ten_a", "ug2", "c1", "auth0|u1", "https://api.test", "read:things", "write:things")
		again.CreatedAt, again.UpdatedAt = ts(5*time.Second), ts(5*time.Second)
		got, err = s.UserGrants().Upsert(ctx, again)
		mustNoErr(t, err)
		want := newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read:things", "write:things")
		want.UpdatedAt = ts(5 * time.Second)
		mustEqual(t, got, want)
		found, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, found, want)

		mustNoErr(t, s.UserGrants().Delete(ctx, "ten_a", "ug1"))
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.UserGrants().Delete(ctx, "ten_a", "ug1"), store.ErrNotFound)
	})

	t.Run("ListAndDeleteByUser", func(t *testing.T) {
		s := open(t, newStore)
		for _, g := range []*store.UserGrant{
			newUserGrant("ten_a", "ug3", "c2", "auth0|u1", "https://api.test", "a"),
			newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://z.test", "b"),
			newUserGrant("ten_a", "ug2", "c1", "auth0|u1", "https://a.test", "c"),
			newUserGrant("ten_a", "ug4", "c1", "auth0|u2", "https://api.test", "d"),
			newUserGrant("ten_b", "ug5", "c1", "auth0|u1", "https://api.test", "e"),
		} {
			_, err := s.UserGrants().Upsert(ctx, g)
			mustNoErr(t, err)
		}
		list, err := s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		var ids []string
		for _, g := range list {
			ids = append(ids, g.ID)
		}
		mustEqual(t, ids, []string{"ug2", "ug1", "ug3"})

		n, err := s.UserGrants().DeleteByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, n, 3)
		list, err = s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, len(list), 0)
		_, err = s.UserGrants().Find(ctx, "ten_b", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err) // other tenant untouched
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u2", "https://api.test")
		mustNoErr(t, err) // other user untouched
	})

	t.Run("ListByAudience", func(t *testing.T) {
		s := open(t, newStore)
		for _, g := range []*store.UserGrant{
			newUserGrant("ten_a", "ug2", "c1", "auth0|u2", "https://api.test", "read"),
			newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read"),
			newUserGrant("ten_a", "ug3", "c1", "auth0|u1", "https://other.test", "read"),
			newUserGrant("ten_b", "ug4", "c1", "auth0|u1", "https://api.test", "read"),
		} {
			_, err := s.UserGrants().Upsert(ctx, g)
			mustNoErr(t, err)
		}
		list, err := s.UserGrants().ListByAudience(ctx, "ten_a", "https://api.test")
		mustNoErr(t, err)
		var ids []string
		for _, g := range list {
			ids = append(ids, g.ID)
		}
		mustEqual(t, ids, []string{"ug1", "ug2"})
	})

	t.Run("List", func(t *testing.T) {
		s := open(t, newStore)
		for _, g := range []*store.UserGrant{
			newUserGrant("ten_a", "ug3", "c1", "auth0|u2", "https://api.test", "read"),
			newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read"),
			newUserGrant("ten_a", "ug2", "c2", "auth0|u1", "https://other.test", "read"),
			newUserGrant("ten_a", "ug5", "c2", "auth0|u1", "https://api.test", "read"),
			newUserGrant("ten_a", "ug4", "c1", "auth0|u1", "https://other.test", "read"),
			newUserGrant("ten_b", "ug0", "c1", "auth0|u1", "https://api.test", "read"),
		} {
			_, err := s.UserGrants().Upsert(ctx, g)
			mustNoErr(t, err)
		}
		list := func(f store.UserGrantFilter, p store.Page) ([]string, int) {
			t.Helper()
			got, total, err := s.UserGrants().List(ctx, "ten_a", f, p)
			mustNoErr(t, err)
			var ids []string
			for _, g := range got {
				ids = append(ids, g.ID)
			}
			return ids, total
		}
		check := func(name string, f store.UserGrantFilter, p store.Page, wantIDs []string, wantTotal int) {
			t.Helper()
			ids, total := list(f, p)
			if len(wantIDs) == 0 {
				mustEqual(t, len(ids), 0)
			} else {
				mustEqual(t, ids, wantIDs)
			}
			mustEqual(t, total, wantTotal)
		}
		check("All", store.UserGrantFilter{}, store.Page{}, []string{"ug1", "ug2", "ug3", "ug4", "ug5"}, 5)
		check("User", store.UserGrantFilter{UserID: "auth0|u1"}, store.Page{}, []string{"ug1", "ug2", "ug4", "ug5"}, 4)
		check("Client", store.UserGrantFilter{ClientID: "c2"}, store.Page{}, []string{"ug2", "ug5"}, 2)
		check("Audience", store.UserGrantFilter{Audience: "https://api.test"}, store.Page{}, []string{"ug1", "ug3", "ug5"}, 3)
		check("All three", store.UserGrantFilter{UserID: "auth0|u1", ClientID: "c1", Audience: "https://other.test"}, store.Page{}, []string{"ug4"}, 1)
		check("Unknown user", store.UserGrantFilter{UserID: "auth0|nobody"}, store.Page{}, nil, 0)
		check("Case sensitive", store.UserGrantFilter{ClientID: "C1"}, store.Page{}, nil, 0)
		check("Page", store.UserGrantFilter{}, store.Page{Offset: 1, Limit: 2}, []string{"ug2", "ug3"}, 5)
		check("Last page", store.UserGrantFilter{}, store.Page{Offset: 4, Limit: 2}, []string{"ug5"}, 5)
		check("Past the end", store.UserGrantFilter{}, store.Page{Offset: 9, Limit: 2}, nil, 5)
		check("Filter and page", store.UserGrantFilter{UserID: "auth0|u1"}, store.Page{Offset: 2, Limit: 1}, []string{"ug4"}, 4)
		got, _, err := s.UserGrants().List(ctx, "ten_a", store.UserGrantFilter{ClientID: "c2"}, store.Page{})
		mustNoErr(t, err)
		got[0].Scopes[0] = "mutated"
		found, err := s.UserGrants().Find(ctx, "ten_a", "c2", "auth0|u1", "https://other.test")
		mustNoErr(t, err)
		mustEqual(t, found.Scopes, []string{"read"})
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "read:things")
		got, err := s.UserGrants().Upsert(ctx, in)
		mustNoErr(t, err)
		in.Scopes[0], got.Scopes[0] = "mutated", "mutated"
		found, err := s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		mustEqual(t, found.Scopes, []string{"read:things"})
		found.Scopes[0] = "mutated"
		list, err := s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, list[0].Scopes, []string{"read:things"})
	})

	t.Run("ConcurrentUpsert", func(t *testing.T) {
		s := open(t, newStore)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.UserGrants().Upsert(ctx, newUserGrant("ten_a", "ug"+string(rune('a'+i)), "c1", "auth0|u1", "https://api.test", "read:things"))
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			mustNoErr(t, err)
		}
		list, err := s.UserGrants().ListByUser(ctx, "ten_a", "auth0|u1")
		mustNoErr(t, err)
		mustEqual(t, len(list), 1)
	})

	t.Run("RollsBackWithTx", func(t *testing.T) {
		s := open(t, newStore)
		err := s.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.UserGrants().Upsert(ctx, newUserGrant("ten_a", "ug1", "c1", "auth0|u1", "https://api.test", "a")); err != nil {
				return err
			}
			return store.ErrConflict // any error aborts
		})
		mustErrIs(t, err, store.ErrConflict)
		_, err = s.UserGrants().Find(ctx, "ten_a", "c1", "auth0|u1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
