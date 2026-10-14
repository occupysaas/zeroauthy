package identity

import (
	"sync"
	"time"
)

// maxThrottleEntries is the map size at which Attempt prunes expired
// entries. It is not a hard cap: if every entry is still live, the map
// keeps growing.
const maxThrottleEntries = 100_000

// Throttle locks a key after too many attempts within a window. It is
// in-process; each server instance counts separately.
type Throttle struct {
	Now func() time.Time

	max     int
	window  time.Duration
	lockout time.Duration

	mu      sync.Mutex
	entries map[string]*throttleEntry
}

type throttleEntry struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// NewThrottle returns a throttle that locks a key for lockout after
// maxFailures attempts within window. maxFailures below 1 is treated as 1.
func NewThrottle(maxFailures int, window, lockout time.Duration) *Throttle {
	if maxFailures < 1 {
		maxFailures = 1
	}
	return &Throttle{max: maxFailures, window: window, lockout: lockout, entries: map[string]*throttleEntry{}}
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Attempt counts an attempt for key and reports whether it may proceed.
// It returns false while key is locked. The check and the count happen
// under one lock, so callers must call Attempt before verifying
// credentials: concurrent attempts then cannot all pass a check that a
// later failure would enforce.
func (t *Throttle) Attempt(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.entries[key]
	if !ok {
		if len(t.entries) >= maxThrottleEntries {
			t.prune(now)
		}
		e = &throttleEntry{windowStart: now}
		t.entries[key] = e
	} else if now.Before(e.lockedUntil) {
		return false
	} else if now.Sub(e.windowStart) > t.window {
		// The window expired. lockedUntil is left alone, so a lockout
		// longer than the window still holds.
		e.windowStart = now
		e.count = 0
	}
	e.count++
	if e.count >= t.max {
		e.lockedUntil = now.Add(t.lockout)
		e.count = 0
		e.windowStart = now
	}
	return true
}

// Refund undoes one counted attempt for key. It does not clear an active
// lockout. Use it for a key whose successful logins should not accumulate.
func (t *Throttle) Refund(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.entries[key]; ok && e.count > 0 {
		e.count--
	}
}

// Success clears all state for key, including any lockout.
func (t *Throttle) Success(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

// prune removes entries whose window and lockout have both passed. The
// caller holds the lock.
func (t *Throttle) prune(now time.Time) {
	for k, e := range t.entries {
		if now.Sub(e.windowStart) > t.window && !now.Before(e.lockedUntil) {
			delete(t.entries, k)
		}
	}
}

// UserThrottleKey and IPThrottleKey name throttle buckets. The hosted
// login and the password grants share them, so attempts through either
// count against the same limits.
func UserThrottleKey(tenantID, connection, login string) string {
	return "user|" + tenantID + "|" + connection + "|" + NormalizeLogin(login)
}

func IPThrottleKey(tenantID, ip string) string { return "ip|" + tenantID + "|" + ip }
