package sqlstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WithTx runs fn in one database transaction. fn must use the store it is
// given, not the outer one (with SQLite the outer one would block). A nested
// WithTx joins the enclosing transaction; an error or panic from fn rolls
// back. WithTx never retries, because fn may have side effects.
func (s *Store) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.atomic(ctx, func(t *Store) error { return fn(t) })
}
