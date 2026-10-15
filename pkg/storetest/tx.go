package storetest

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testTx(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CommitApplies", func(t *testing.T) {
		s := open(t, newStore)
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("acme")); err != nil {
				return err
			}
			_, err := tx.Tenants().GetByName(ctx, "acme") // reads see the transaction's writes
			return err
		})
		mustNoErr(t, err)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustNoErr(t, err)
	})

	t.Run("ErrorRollsBack", func(t *testing.T) {
		s := open(t, newStore)
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("acme")); err != nil {
				return err
			}
			if err := tx.Clients().Create(ctx, newClient("ten_acme", "c1")); err != nil {
				return err
			}
			return boom
		})
		mustErrIs(t, err, boom)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Clients().Get(ctx, "ten_acme", "c1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ConflictInsideRollsBack", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("globex")); err != nil {
				return err
			}
			return tx.Tenants().Create(ctx, newTenant("acme")) // conflict
		})
		mustErrIs(t, err, store.ErrConflict)
		_, err = s.Tenants().GetByName(ctx, "globex")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("NestedRunsInline", func(t *testing.T) {
		s := open(t, newStore)
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("acme")); err != nil {
				return err
			}
			if err := tx.WithTx(ctx, func(inner store.Store) error {
				return inner.Tenants().Create(ctx, newTenant("globex"))
			}); err != nil {
				return err
			}
			return boom
		})
		mustErrIs(t, err, boom)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().GetByName(ctx, "globex")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("NestedCommitsWithOuter", func(t *testing.T) {
		s := open(t, newStore)
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("acme")); err != nil {
				return err
			}
			return tx.WithTx(ctx, func(inner store.Store) error {
				return inner.Tenants().Create(ctx, newTenant("globex"))
			})
		})
		mustNoErr(t, err)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustNoErr(t, err)
		_, err = s.Tenants().GetByName(ctx, "globex")
		mustNoErr(t, err)
	})
}
