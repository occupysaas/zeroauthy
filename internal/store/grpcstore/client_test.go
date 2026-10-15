package grpcstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A panic inside fn rolls the remote transaction back and is re-raised.
func TestClientWithTxPanicRollsBack(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		_ = c.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "p", Name: "p"}); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if _, err := c.Tenants().Get(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after panic: %v", err)
	}
	// The server-side transaction was released: another WithTx proceeds.
	if err := c.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// Cancelling ctx inside fn still rolls back (Rollback uses WithoutCancel).
func TestClientWithTxCancelledContext(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	err := c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "c", Name: "c"}); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Tenants().Get(context.Background(), "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after cancel: %v", err)
	}
}

// Transport failures are errors, not domain errors.
func TestClientTransportErrorIsNotADomainError(t *testing.T) {
	c := inProcess(t)
	c.Close()
	_, err := c.Tenants().Get(context.Background(), "x")
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want a transport error", err)
	}
}
