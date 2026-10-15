package store_test

import (
	"errors"
	"testing"

	internal "github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/store"
)

// The aliases are the same types, so values flow both ways without conversion.
func TestAliasesAreIdentical(t *testing.T) {
	var s store.Store = memory.New()
	var _ internal.Store = s
	var u *store.User = &internal.User{}
	_ = u
	if !errors.Is(internal.ErrNotFound, store.ErrNotFound) ||
		!errors.Is(internal.ErrConflict, store.ErrConflict) ||
		!errors.Is(internal.ErrAlreadyUsed, store.ErrAlreadyUsed) {
		t.Fatal("sentinel errors differ")
	}
	if store.KeyCurrent != internal.KeyCurrent || store.StrategyDatabase != internal.StrategyDatabase {
		t.Fatal("constants differ")
	}
}
