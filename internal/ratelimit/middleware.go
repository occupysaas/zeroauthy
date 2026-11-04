package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
)

// Group names a set of endpoints that share one bucket per tenant and IP.
type Group string

const (
	GroupToken     Group = "token"     // /oauth/token, every grant
	GroupAuthorize Group = "authorize" // /authorize
	GroupUserinfo  Group = "userinfo"  // /userinfo
	GroupDiscovery Group = "discovery" // /.well-known/*, JWKS included
	GroupOther     Group = "other"     // every other tenant Authentication API route
)

// Groups lists every group.
var Groups = []Group{GroupToken, GroupAuthorize, GroupUserinfo, GroupDiscovery, GroupOther}

// Config is security.rate_limit.
type Config struct {
	Enabled bool
	// MaxKeys caps the tracked (tenant, IP) pairs of each group.
	MaxKeys int
	Groups  map[Group]Rate
}

// Middleware limits requests per (tenant, client IP, group).
type Middleware struct {
	limiters map[Group]*Limiter
}

// New returns the middleware for cfg; nil when cfg is disabled, which
// passes every request through.
func New(cfg Config) *Middleware {
	if !cfg.Enabled {
		return nil
	}
	m := &Middleware{limiters: map[Group]*Limiter{}}
	for g, r := range cfg.Groups {
		m.limiters[g] = NewLimiter(r, cfg.MaxKeys)
	}
	return m
}

// KeyFunc names a request's tenant, client IP and group; ok false leaves
// the request unlimited.
type KeyFunc func(*http.Request) (tenant, ip string, group Group, ok bool)

// Handler limits requests by key. Every answer on a limited route carries
// X-RateLimit-Limit, X-RateLimit-Remaining and X-RateLimit-Reset (a UNIX
// time in seconds); Auth0 sends them on successful and throttled responses
// alike, and throttles with 429 too_many_requests and Retry-After:
// https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/custom-rate-limit-policies
func (m *Middleware) Handler(key KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if m == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ip, group, ok := key(r)
			l := m.limiters[group]
			if !ok || l == nil {
				next.ServeHTTP(w, r)
				return
			}
			d := l.Allow(tenant + "\x00" + httpx.IPBucket(ip))
			h := w.Header()
			h.Set("X-RateLimit-Limit", strconv.Itoa(d.Limit))
			h.Set("X-RateLimit-Remaining", strconv.Itoa(d.Remaining))
			h.Set("X-RateLimit-Reset", strconv.FormatInt(ceilUnix(d.Reset), 10))
			if !d.Allowed {
				WriteTooManyRequests(w, d.RetryAfter)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteTooManyRequests writes Auth0's 429 body, with Retry-After in whole
// seconds (at least 1).
func WriteTooManyRequests(w http.ResponseWriter, retryAfter time.Duration) {
	secs := int64(math.Ceil(retryAfter.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteError(w, http.StatusTooManyRequests, "too_many_requests", "Rate limit exceeded.")
}

func ceilUnix(t time.Time) int64 {
	s := t.Unix()
	if t.Nanosecond() > 0 {
		s++
	}
	return s
}
