package storetest

import (
	"context"
	"errors"
	"fmt"
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

	t.Run("HandledConflictContinues", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_acme", "h1")))
		err := s.WithTx(ctx, func(tx store.Store) error {
			dup := newAuthCode("ten_acme", "h1")
			dup.ClientID = "other"
			if err := tx.AuthCodes().Create(ctx, dup); !errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("duplicate code: %w", err)
			}
			// A write that fails part-way (the tenant row, then a domain
			// owned by acme) leaves nothing behind.
			steal := newTenant("globex")
			steal.Domains = []string{"globex.example.test", "acme.example.test"}
			if err := tx.Tenants().Create(ctx, steal); !errors.Is(err, store.ErrConflict) {
				return fmt.Errorf("stolen domain: %w", err)
			}
			if err := tx.AuthCodes().Create(ctx, newAuthCode("ten_acme", "h2")); err != nil {
				return err
			}
			return tx.Tenants().Create(ctx, newTenant("initech"))
		})
		mustNoErr(t, err)
		got, err := s.AuthCodes().Get(ctx, "ten_acme", "h1")
		mustNoErr(t, err)
		mustEqual(t, got, newAuthCode("ten_acme", "h1"))
		_, err = s.AuthCodes().Get(ctx, "ten_acme", "h2")
		mustNoErr(t, err)
		_, err = s.Tenants().Get(ctx, "ten_globex")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().GetByDomain(ctx, "globex.example.test")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().Get(ctx, "ten_initech")
		mustNoErr(t, err)
	})

	t.Run("NestedErrorRollsBackInnerOnly", func(t *testing.T) {
		s := open(t, newStore)
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, newTenant("acme")); err != nil {
				return err
			}
			err := tx.WithTx(ctx, func(inner store.Store) error {
				if err := inner.Tenants().Create(ctx, newTenant("globex")); err != nil {
					return err
				}
				return boom
			})
			if !errors.Is(err, boom) {
				return fmt.Errorf("nested: %w", err)
			}
			_, err = tx.Tenants().GetByName(ctx, "globex") // already gone inside the outer transaction
			if !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("inner write visible after its rollback: %v", err)
			}
			return nil
		})
		mustNoErr(t, err)
		_, err = s.Tenants().GetByName(ctx, "acme")
		mustNoErr(t, err)
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
