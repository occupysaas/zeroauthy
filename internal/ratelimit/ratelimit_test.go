package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(rate float64, burst, maxKeys int) (*Limiter, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := NewLimiter(Rate{PerSecond: rate, Burst: burst}, maxKeys)
	l.now = c.now
	return l, c
}

func TestBucketBurstThenRefill(t *testing.T) {
	l, c := newTestLimiter(2, 3, 10)
	for i := range 3 {
		if d := l.Allow("k"); !d.Allowed || d.Remaining != 2-i {
			t.Fatalf("request %d: %+v", i, d)
		}
	}
	d := l.Allow("k")
	if d.Allowed || d.Remaining != 0 {
		t.Fatalf("over burst allowed: %+v", d)
	}
	// One token comes back after 1/rate seconds.
	if d.RetryAfter != 500*time.Millisecond {
		t.Fatalf("retry after = %s", d.RetryAfter)
	}
	c.advance(500 * time.Millisecond)
	if d := l.Allow("k"); !d.Allowed {
		t.Fatalf("refilled token refused: %+v", d)
	}
	if d := l.Allow("k"); d.Allowed {
		t.Fatalf("only one token should have refilled: %+v", d)
	}
	// The bucket never holds more than its burst.
	c.advance(time.Hour)
	for i := range 3 {
		if !l.Allow("k").Allowed {
			t.Fatalf("request %d after idle refused", i)
		}
	}
	if l.Allow("k").Allowed {
		t.Fatal("bucket refilled beyond burst")
	}
}

func TestDecisionReset(t *testing.T) {
	l, c := newTestLimiter(1, 4, 10)
	l.Allow("k")
	l.Allow("k")
	d := l.Allow("k")
	// Three tokens spent at 1/s: the bucket is full again in 3s.
	if want := c.t.Add(3 * time.Second); !d.Reset.Equal(want) {
		t.Fatalf("reset = %s, want %s", d.Reset, want)
	}
	if d.Limit != 4 {
		t.Fatalf("limit = %d", d.Limit)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(1, 1, 10)
	if !l.Allow("a").Allowed || l.Allow("a").Allowed {
		t.Fatal("a: want one allowed then refused")
	}
	if !l.Allow("b").Allowed {
		t.Fatal("a's bucket throttled b")
	}
}

func TestTrackedKeysAreBounded(t *testing.T) {
	l, _ := newTestLimiter(1, 1, 100)
	for i := range 10_000 {
		l.Allow(fmt.Sprintf("spoofed-%d", i))
	}
	if n := l.Len(); n > 100 {
		t.Fatalf("tracking %d keys, cap 100", n)
	}
}

func TestEvictionDropsLeastRecentlyUsed(t *testing.T) {
	l, c := newTestLimiter(1, 2, 3)
	// "hot" is drained and stays recent; the others are refilled (idle).
	l.Allow("hot")
	l.Allow("hot")
	l.Allow("idle1")
	l.Allow("idle2")
	c.advance(10 * time.Second)
	l.Allow("hot")
	l.Allow("hot")
	// Two new keys push out the least recently used, never "hot".
	l.Allow("new1")
	l.Allow("new2")
	if l.Allow("hot").Allowed {
		t.Fatal("hot key was evicted and its limit reset")
	}
}

func testConfig(rate float64, burst int) Config {
	r := Rate{PerSecond: rate, Burst: burst}
	return Config{Enabled: true, MaxKeys: 1000, Groups: map[Group]Rate{
		GroupToken: r, GroupAuthorize: r, GroupUserinfo: r, GroupDiscovery: r, GroupOther: r,
	}}
}

func serve(m *Middleware, tenant, ip string, group Group) *httptest.ResponseRecorder {
	h := m.Handler(func(r *http.Request) (string, string, Group, bool) {
		return tenant, ip, group, true
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))
	return rec
}

func TestMiddlewareKeySeparation(t *testing.T) {
	m := New(testConfig(0.001, 1))
	if serve(m, "t1", "192.0.2.1", GroupToken).Code != http.StatusOK {
		t.Fatal("first request refused")
	}
	if serve(m, "t1", "192.0.2.1", GroupToken).Code != http.StatusTooManyRequests {
		t.Fatal("second request allowed")
	}
	for name, c := range map[string]struct {
		tenant, ip string
		group      Group
	}{
		"other tenant": {"t2", "192.0.2.1", GroupToken},
		"other ip":     {"t1", "192.0.2.2", GroupToken},
		"other group":  {"t1", "192.0.2.1", GroupUserinfo},
	} {
		if code := serve(m, c.tenant, c.ip, c.group).Code; code != http.StatusOK {
			t.Errorf("%s: status %d, want its own bucket", name, code)
		}
	}
	// One IPv6 host owns its /64: rotating addresses inside it does not help.
	serve(m, "t1", "2001:db8:1:2::1", GroupToken)
	if serve(m, "t1", "2001:db8:1:2::ffff", GroupToken).Code != http.StatusTooManyRequests {
		t.Error("IPv6 /64 not bucketed")
	}
}

// Auth0 answers 429 too_many_requests with X-RateLimit-* and Retry-After:
// https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/custom-rate-limit-policies
func TestTooManyRequestsResponse(t *testing.T) {
	m := New(testConfig(0.5, 1))
	ok := serve(m, "t", "192.0.2.1", GroupToken)
	if ok.Header().Get("X-RateLimit-Limit") != "1" || ok.Header().Get("X-RateLimit-Remaining") != "0" || ok.Header().Get("X-RateLimit-Reset") == "" {
		t.Fatalf("success headers = %v", ok.Header())
	}
	rec := serve(m, "t", "192.0.2.1", GroupToken)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "too_many_requests" || body["error_description"] == "" || len(body) != 2 {
		t.Fatalf("body = %v", body)
	}
	h := rec.Header()
	if h.Get("Content-Type") != "application/json" || h.Get("X-RateLimit-Limit") != "1" || h.Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("headers = %v", h)
	}
	reset, err := strconv.ParseInt(h.Get("X-RateLimit-Reset"), 10, 64)
	if err != nil || reset < time.Now().Unix() || reset > time.Now().Add(3*time.Second).Unix() {
		t.Fatalf("X-RateLimit-Reset = %q, want a UNIX time within the refill period", h.Get("X-RateLimit-Reset"))
	}
	if h.Get("Retry-After") != "2" {
		t.Fatalf("Retry-After = %q", h.Get("Retry-After"))
	}
}

func TestDisabledPassesThrough(t *testing.T) {
	cfg := testConfig(0.001, 1)
	cfg.Enabled = false
	m := New(cfg)
	for range 5 {
		rec := serve(m, "t", "192.0.2.1", GroupToken)
		if rec.Code != http.StatusOK || rec.Header().Get("X-RateLimit-Limit") != "" {
			t.Fatalf("disabled limiter acted: %d %v", rec.Code, rec.Header())
		}
	}
	var nilM *Middleware
	if serve(nilM, "t", "192.0.2.1", GroupToken).Code != http.StatusOK {
		t.Fatal("nil middleware refused")
	}
}

func TestSemaphoreCapsConcurrency(t *testing.T) {
	s := NewSemaphore(2, 0)
	r1, ok1 := s.Acquire(context.Background())
	r2, ok2 := s.Acquire(context.Background())
	if !ok1 || !ok2 {
		t.Fatal("slots under the cap refused")
	}
	if _, ok := s.Acquire(context.Background()); ok {
		t.Fatal("third concurrent acquire allowed over cap 2")
	}
	r1()
	r3, ok := s.Acquire(context.Background())
	if !ok {
		t.Fatal("released slot not reusable")
	}
	r2()
	r3()
	var nilS *Semaphore
	if rel, ok := nilS.Acquire(context.Background()); !ok {
		t.Fatal("nil semaphore refused")
	} else {
		rel()
	}
}

func TestSemaphoreWaitIsBounded(t *testing.T) {
	s := NewSemaphore(1, 20*time.Millisecond)
	rel, _ := s.Acquire(context.Background())
	start := time.Now()
	if _, ok := s.Acquire(context.Background()); ok {
		t.Fatal("acquired a held slot")
	}
	if d := time.Since(start); d < 15*time.Millisecond || d > time.Second {
		t.Fatalf("waited %s", d)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		rel()
	}()
	if rel2, ok := s.Acquire(context.Background()); !ok {
		t.Fatal("slot released during the wait was not taken")
	} else {
		rel2()
	}
	wg.Wait()
}
