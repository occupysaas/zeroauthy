package store

import (
	"context"
	"time"
)

// SessionExpiryLister supplies bounded snapshots for transactional expiry
// notifications. The caller reloads/locks and rechecks each session before ending it.
type SessionExpiryLister interface {
	ListExpired(context.Context, time.Time, int) ([]*LoginSession, error)
}
