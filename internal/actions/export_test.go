package actions

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// EnqueueBoundForTest queues a job for bindings the store would now refuse,
// such as several custom-email-provider Actions bound before the one-binding
// limit, so the worker's handling of such jobs stays covered.
func (e *Engine) EnqueueBoundForTest(ctx context.Context, tx store.Store, j AsyncJob, bound []store.BoundVersion) error {
	return e.enqueueBound(ctx, tx, j, bound)
}
