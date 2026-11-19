package store

import (
	"context"
	"time"
)

// DPoP tracks proof use across requests and replicas. Only the digest of jti
// is retained. UseProof atomically claims a tenant/origin/key/jti tuple until
// expiresAt, returning ErrConflict on reuse and ErrInvalid for expired claims.
type DPoP interface {
	UseProof(ctx context.Context, tid, origin, jkt, jti string, now, expiresAt time.Time) error
	// PurgeBefore deletes at most limit entries expiring on or before before.
	PurgeBefore(ctx context.Context, before time.Time, limit int) (int, error)
}
