package store

import (
	"context"
	"errors"
	"time"
)

// ErrSessionLimitsUnavailable: the driver (or a plugin built before Plan 40)
// cannot set session limits.
var ErrSessionLimitsUnavailable = errors.New("store: session limits unavailable")

// SessionLimitSetter is the optional Plan 40 session update behind
// api.session.setExpiresAt, setIdleExpiresAt and setCookieMode. Callers cap
// the values (they may only shorten); the store writes them as given and
// returns the updated session, or ErrNotFound.
type SessionLimitSetter interface {
	SetLimits(ctx context.Context, tenantID, id string, expiresAt, idleExpiresAt time.Time, cookieMode string) (*LoginSession, error)
}

// SetSessionLimits applies SetLimits through st's sessions, or returns
// ErrSessionLimitsUnavailable when the driver lacks it (the flow then fails closed).
func SetSessionLimits(ctx context.Context, st Store, tenantID, id string, expiresAt, idleExpiresAt time.Time, cookieMode string) (*LoginSession, error) {
	s, ok := st.Sessions().(SessionLimitSetter)
	if !ok {
		return nil, ErrSessionLimitsUnavailable
	}
	return s.SetLimits(ctx, tenantID, id, expiresAt, idleExpiresAt, cookieMode)
}
