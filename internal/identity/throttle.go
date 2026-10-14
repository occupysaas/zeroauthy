package identity

import (
	"sync"
	"time"
)

// maxThrottleEntries bounds memory. Expired entries are pruned when the
// map grows past it.
const maxThrottleEntries = 100_000

// Throttle locks a key after too many failures within a window. It is
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
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

func NewThrottle(maxFailures int, window, lockout time.Duration) *Throttle {
	return &Throttle{max: maxFailures, window: window, lockout: lockout, entries: map[string]*throttleEntry{}}
}

func (t *Throttle) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Allowed reports whether an attempt for key may proceed.
func (t *Throttle) Allowed(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[key]
	return !ok || !t.now().Before(e.lockedUntil)
}

// Failure records a failed attempt.
func (t *Throttle) Failure(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.entries[key]
	if !ok || now.Sub(e.windowStart) > t.window {
		if len(t.entries) >= maxThrottleEntries {
			t.prune(now)
		}
		e = &throttleEntry{windowStart: now}
		t.entries[key] = e
	}
	e.failures++
	if e.failures >= t.max {
		e.lockedUntil = now.Add(t.lockout)
		e.failures = 0
		e.windowStart = now
	}
}

// Success clears the failures for key.
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
