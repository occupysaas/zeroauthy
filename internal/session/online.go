package session

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

// IdleExpiry applies the tenant's current idle policy, bounded by the existing
// absolute lifetime; an online-token exchange cannot restart that lifetime.
func IdleExpiry(t *store.Tenant, s *store.LoginSession, now time.Time) time.Time {
	_, idle := lifetimes(t, s.CookieMode)
	return minTime(expiry(now, idle), s.ExpiresAt)
}
