package storetest

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"sync"
	"testing"
	"time"
)

func testConnectionKeys(t *testing.T, factory Factory) {
	ctx := context.Background()
	setup := func(t *testing.T) store.Store {
		s := open(t, factory)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		mustNoErr(t, s.Connections().Create(ctx, &store.Connection{TenantID: "ten_a", ID: "con_keys", Name: "keys", Strategy: "oidc"}))
		return s
	}
	key := func(use, kid, state string) *store.ConnectionKey {
		return &store.ConnectionKey{TenantID: "ten_a", ConnectionID: "con_keys", KID: kid, Use: use, Alg: "RS256", State: state, CertDER: []byte{1, 2}, PrivateSealed: []byte{3, 4}, CreatedAt: ts(0)}
	}
	create := func(t *testing.T, s store.Store, use string) {
		t.Helper()
		mustNoErr(t, s.ConnectionKeys().Create(ctx, "ten_a", "con_keys", use, key(use, use+"1", "current"), key(use, use+"2", "next")))
	}
	t.Run("KeysCreateConflict", func(t *testing.T) {
		s := setup(t)
		create(t, s, "signing")
		mustErrIs(t, s.ConnectionKeys().Create(ctx, "ten_a", "con_keys", "signing", key("signing", "x", "current"), key("signing", "y", "next")), store.ErrConflict)
		create(t, s, "encryption")
	})
	t.Run("KeysListOrder", func(t *testing.T) {
		s := setup(t)
		create(t, s, "encryption")
		create(t, s, "signing")
		list, e := s.ConnectionKeys().List(ctx, "ten_a", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, len(list), 4)
		mustEqual(t, list[0].KID, "signing1")
		mustEqual(t, list[1].KID, "signing2")
		mustEqual(t, list[2].KID, "encryption1")
		list[0].CertDER[0] = 9
		again, e := s.ConnectionKeys().List(ctx, "ten_a", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, again[0].CertDER[0], byte(1))
	})
	t.Run("KeysRotate", func(t *testing.T) {
		s := setup(t)
		create(t, s, "signing")
		now := ts(time.Hour)
		current, e := s.ConnectionKeys().Rotate(ctx, "ten_a", "con_keys", "signing", key("signing", "signing3", "next"), now)
		mustNoErr(t, e)
		mustEqual(t, current.KID, "signing2")
		mustEqual(t, *current.CurrentSince, now)
		list, e := s.ConnectionKeys().List(ctx, "ten_a", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, len(list), 3)
		mustEqual(t, list[0].State, "current")
		mustEqual(t, list[1].State, "next")
		mustEqual(t, list[2].State, "previous")
	})
	t.Run("KeysRotateNone", func(t *testing.T) {
		s := setup(t)
		_, e := s.ConnectionKeys().Rotate(ctx, "ten_a", "con_keys", "signing", key("signing", "n", "next"), ts(0))
		mustErrIs(t, e, store.ErrNotFound)
	})
	t.Run("RotateOneWinner", func(t *testing.T) {
		s := setup(t)
		create(t, s, "signing")
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Go(func() {
				_, e := s.ConnectionKeys().Rotate(ctx, "ten_a", "con_keys", "signing", key("signing", fmt.Sprint("new", i), "next"), ts(time.Hour))
				errs <- e
			})
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				mustErrIs(t, e, store.ErrConflict)
			}
		}
		list, e := s.ConnectionKeys().List(ctx, "ten_a", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, len(list), 3)
		seen := map[string]bool{}
		for _, k := range list {
			if seen[k.State] {
				t.Fatal("duplicate state")
			}
			seen[k.State] = true
		}
	})
	t.Run("KeysCascade", func(t *testing.T) {
		s := setup(t)
		create(t, s, "signing")
		mustNoErr(t, s.Connections().Delete(ctx, "ten_a", "con_keys"))
		list, e := s.ConnectionKeys().List(ctx, "ten_a", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, len(list), 0)
	})
	t.Run("KeysTenantIsolation", func(t *testing.T) {
		s := setup(t)
		create(t, s, "signing")
		list, e := s.ConnectionKeys().List(ctx, "ten_b", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, len(list), 0)
	})
	t.Run("KeysRollback", func(t *testing.T) {
		s := setup(t)
		e := s.WithTx(ctx, func(tx store.Store) error { create(t, tx, "signing"); return store.ErrInvalid })
		mustErrIs(t, e, store.ErrInvalid)
		list, e := s.ConnectionKeys().List(ctx, "ten_a", "con_keys")
		mustNoErr(t, e)
		mustEqual(t, len(list), 0)
	})
}
