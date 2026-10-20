package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// A write made outside any transaction while one runs is not undone when
// that transaction rolls back: it waits for the transaction instead.
func TestRollbackKeepsOutsideWrites(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	u := &store.User{TenantID: "t", UserID: "auth0|u1", Email: "u1@example.test",
		Identities: []store.Identity{{Connection: "Database", Provider: "auth0", UserID: "u1"}}}
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	deleted := make(chan error, 1)
	errFail := errors.New("roll back")
	err := s.WithTx(ctx, func(tx store.Store) error {
		// The snapshot is taken; a delete outside the transaction starts.
		go func() { deleted <- s.Users().Delete(ctx, "t", "auth0|u1") }()
		select {
		case err := <-deleted:
			// Ran inside the transaction: the rollback below would undo it.
			deleted <- err
		case <-time.After(50 * time.Millisecond):
		}
		if _, err := tx.Users().BumpVersion(ctx, "t", "auth0|u1"); err != nil {
			return err
		}
		return errFail
	})
	if !errors.Is(err, errFail) {
		t.Fatalf("WithTx = %v", err)
	}
	if err := <-deleted; err != nil {
		t.Fatalf("delete = %v", err)
	}
	if _, err := s.Users().Get(ctx, "t", "auth0|u1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user after the rollback = %v; the delete was undone", err)
	}
}
