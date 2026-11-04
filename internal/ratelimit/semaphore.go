package ratelimit

import (
	"context"
	"runtime"
	"time"
)

// Semaphore caps concurrent expensive work, such as legacy argon2id client
// secret verifications (19 MiB each). A caller waits at most wait for a
// slot and is then refused, so a flood never queues without bound.
type Semaphore struct {
	slots chan struct{}
	wait  time.Duration
}

// NewSemaphore returns a semaphore with n slots (at least 1).
func NewSemaphore(n int, wait time.Duration) *Semaphore {
	if n < 1 {
		n = 1
	}
	return &Semaphore{slots: make(chan struct{}, n), wait: wait}
}

// Acquire takes a slot; ok false means none freed in time. A nil semaphore
// is unlimited. Call release exactly once after the work.
func (s *Semaphore) Acquire(ctx context.Context) (release func(), ok bool) {
	if s == nil {
		return func() {}, true
	}
	select {
	case s.slots <- struct{}{}:
		return s.release, true
	default:
	}
	if s.wait <= 0 {
		return nil, false
	}
	t := time.NewTimer(s.wait)
	defer t.Stop()
	select {
	case s.slots <- struct{}{}:
		return s.release, true
	case <-t.C:
	case <-ctx.Done():
	}
	return nil, false
}

func (s *Semaphore) release() { <-s.slots }

// SecretVerificationWait is how long a legacy secret check waits for a
// slot before the request is refused.
const SecretVerificationWait = 100 * time.Millisecond

// NewSecretVerifications returns the per-process cap on legacy client
// secret checks: n slots, or GOMAXPROCS (at least 4) when n is 0.
func NewSecretVerifications(n int) *Semaphore {
	if n <= 0 {
		n = max(4, runtime.GOMAXPROCS(0))
	}
	return NewSemaphore(n, SecretVerificationWait)
}
