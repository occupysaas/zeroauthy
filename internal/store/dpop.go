package store

import (
	"context"
	"errors"
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

// RefreshTokensIISupporter negotiates refresh_tokens_ii.v1 for remote stores.
type RefreshTokensIISupporter interface{ CheckRefreshTokensIISupport(context.Context) error }

// ErrRefreshTokensIISupportLost means a previously capable connection can no
// longer serve protected operations. It never authorizes a legacy retry.
var ErrRefreshTokensIISupportLost = errors.New("store: negotiated refresh_tokens_ii.v1 support lost")

// CheckRefreshTokensIISupport preserves the difference between a legacy
// plugin, lost support, and a communication failure. Only ErrRefreshTokensIIUnavailable
// from this probe authorizes legacy semantics. An error from an actual protected
// operation never authorizes retry through a legacy method. Built-in stores
// implement the capability unconditionally.
func CheckRefreshTokensIISupport(ctx context.Context, s Store) error {
	if cap, ok := s.(RefreshTokensIISupporter); ok {
		return cap.CheckRefreshTokensIISupport(ctx)
	}
	return nil
}
