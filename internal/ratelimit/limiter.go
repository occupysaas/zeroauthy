// Package ratelimit holds the general Authentication API request limiter
// and the cap on concurrent expensive verifications.
//
// Auth0 limits the Authentication API with token buckets (the bucket size
// is the burst, the refill rate the sustained rate):
// https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy
//
// Counters live in this process only: N replicas allow N times the rate.
// Shared counters are Plan 45.
package ratelimit

import (
	"container/list"
	"math"
	"sync"
	"time"
)

// Rate is a token bucket: Burst requests at once, refilled at PerSecond.
type Rate struct {
	PerSecond float64
	Burst     int
}

// Decision is the outcome of one request against a bucket.
type Decision struct {
	Allowed bool
	// Limit is the bucket size; Remaining the whole tokens left after this
	// request.
	Limit     int
	Remaining int
	// Reset is when the bucket is full again.
	Reset time.Time
	// RetryAfter is how long until one token is available (refused only).
	RetryAfter time.Duration
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// Limiter keeps one token bucket per key and tracks at most maxKeys keys.
// When full, the least recently used key is dropped: under a flood of
// distinct (spoofed) keys memory stays bounded, and a dropped bucket only
// starts again full, which an idle bucket already is.
type Limiter struct {
	rate    Rate
	maxKeys int
	now     func() time.Time

	mu    sync.Mutex
	keys  map[string]*list.Element
	order *list.List // front: most recently used
}

// NewLimiter returns a limiter for rate tracking at most maxKeys keys
// (at least 1).
func NewLimiter(rate Rate, maxKeys int) *Limiter {
	if maxKeys < 1 {
		maxKeys = 1
	}
	if rate.Burst < 1 {
		rate.Burst = 1
	}
	return &Limiter{rate: rate, maxKeys: maxKeys, now: time.Now, keys: map[string]*list.Element{}, order: list.New()}
}

// Len is the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// Allow spends one token of key's bucket if it has one.
func (l *Limiter) Allow(key string) Decision {
	now := l.now()
	burst := float64(l.rate.Burst)
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *bucket
	if e, ok := l.keys[key]; ok {
		l.order.MoveToFront(e)
		b = e.Value.(*bucket)
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = math.Min(burst, b.tokens+elapsed*l.rate.PerSecond)
		}
		b.last = now
	} else {
		for len(l.keys) >= l.maxKeys {
			oldest := l.order.Back()
			l.order.Remove(oldest)
			delete(l.keys, oldest.Value.(*bucket).key)
		}
		b = &bucket{key: key, tokens: burst, last: now}
		l.keys[key] = l.order.PushFront(b)
	}
	d := Decision{Limit: l.rate.Burst}
	if b.tokens >= 1 {
		b.tokens--
		d.Allowed = true
	} else {
		d.RetryAfter = l.duration(1 - b.tokens)
	}
	d.Remaining = int(math.Floor(b.tokens))
	d.Reset = now.Add(l.duration(burst - b.tokens))
	return d
}

// duration is how long the bucket takes to refill n tokens.
func (l *Limiter) duration(n float64) time.Duration {
	if l.rate.PerSecond <= 0 {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(n / l.rate.PerSecond * float64(time.Second))
}
