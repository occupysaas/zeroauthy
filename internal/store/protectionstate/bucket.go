// Package protectionstate implements driver-independent protection transitions.
// Callers serialize transitions and persist buckets with their memberships atomically.
package protectionstate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const PendingLifetime = time.Minute

type Member struct {
	Generation string
	Sequence   int64
	Outcome    string
	ReservedAt time.Time
}
type Bucket struct {
	ID, Generation                     string
	Limit                              store.ProtectionLimit
	Tokens                             float64
	NextSequence                       int64
	UpdatedAt, BlockedUntil, ExpiresAt time.Time
	Members                            map[string]Member
}

func ID(k store.ProtectionKey) string {
	b, _ := json.Marshal(k)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func NewID() string { return rand.Text() }
func Validate(ls []store.ProtectionLimit) error {
	seen := map[store.ProtectionKey]bool{}
	tenant := ""
	for _, l := range ls {
		if l.Key.TenantID == "" || l.Key.Kind == "" || l.Capacity <= 0 || seen[l.Key] || (tenant != "" && tenant != l.Key.TenantID) {
			return store.ErrInvalid
		}
		tenant = l.Key.TenantID
		seen[l.Key] = true
		switch l.Algorithm {
		case "brute-force":
			if l.Lockout <= 0 {
				return store.ErrInvalid
			}
		case "fixed-window":
			if l.Window <= 0 {
				return store.ErrInvalid
			}
		case "token-bucket":
			if l.Refill <= 0 || int64(l.Refill) > math.MaxInt64/int64(l.Capacity) {
				return store.ErrInvalid
			}
		default:
			return store.ErrInvalid
		}
	}
	return nil
}
func New(id, gen string, l store.ProtectionLimit, now time.Time) *Bucket {
	b := &Bucket{ID: id, Generation: gen, Limit: l, Tokens: float64(l.Capacity), UpdatedAt: now, Members: map[string]Member{}}
	switch l.Algorithm {
	case "fixed-window":
		b.ExpiresAt = now.Add(l.Window)
	case "brute-force":
		b.ExpiresAt = now.Add(l.Lockout)
	case "token-bucket":
		b.ExpiresAt = now.Add(time.Duration(l.Capacity) * l.Refill)
	}
	return b
}
func (b *Bucket) Clone() *Bucket {
	c := *b
	c.Members = map[string]Member{}
	for k, v := range b.Members {
		c.Members[k] = v
	}
	return &c
}
func (b *Bucket) Matches(l store.ProtectionLimit) bool {
	old := b.Limit
	if old.Algorithm == "brute-force" && l.Algorithm == old.Algorithm && l.Capacity < old.Capacity {
		old.Capacity = l.Capacity
	}
	return old == l
}
func (b *Bucket) Advance(now time.Time) {
	if b.Limit.Algorithm == "token-bucket" && now.After(b.UpdatedAt) {
		b.Tokens = math.Min(float64(b.Limit.Capacity), b.Tokens+float64(now.Sub(b.UpdatedAt))/float64(b.Limit.Refill))
		b.UpdatedAt = now
	}
	for id, m := range b.Members {
		if m.Outcome == "pending" && !now.Before(m.ReservedAt.Add(PendingLifetime)) {
			b.finish(id, "failure", m.ReservedAt.Add(PendingLifetime))
		}
	}
}
func (b *Bucket) Counts() (failure, pending int) {
	for _, m := range b.Members {
		if m.Generation != b.Generation {
			continue
		}
		switch m.Outcome {
		case "pending":
			pending++
		case "failure":
			failure++
		}
	}
	return
}
func (b *Bucket) RetryAt(now time.Time) time.Time {
	f, p := b.Counts()
	switch b.Limit.Algorithm {
	case "token-bucket":
		if b.Tokens < 1 {
			return now.Add(time.Duration(math.Ceil((1 - b.Tokens) * float64(b.Limit.Refill))))
		}
	case "fixed-window":
		if f+p >= b.Limit.Capacity {
			return b.ExpiresAt
		}
	case "brute-force":
		if f+p >= b.Limit.Capacity {
			return b.ExpiresAt
		}
	}
	return time.Time{}
}
func (b *Bucket) Reserve(id string, now time.Time) {
	b.NextSequence++
	b.Members[id] = Member{Generation: b.Generation, Sequence: b.NextSequence, Outcome: "pending", ReservedAt: now}
	if b.Limit.Algorithm == "token-bucket" {
		b.Tokens--
		b.ExpiresAt = now.Add(time.Duration(b.Limit.Capacity) * b.Limit.Refill)
	}
}
func (b *Bucket) Complete(id, outcome string, now time.Time) {
	m, ok := b.Members[id]
	if !ok {
		return
	}
	if b.Limit.Algorithm == "token-bucket" && now.After(b.UpdatedAt) {
		b.Tokens = math.Min(float64(b.Limit.Capacity), b.Tokens+float64(now.Sub(b.UpdatedAt))/float64(b.Limit.Refill))
		b.UpdatedAt = now
	}
	completedAt := now
	if !now.Before(m.ReservedAt.Add(PendingLifetime)) {
		outcome = "failure"
		completedAt = m.ReservedAt.Add(PendingLifetime)
	}
	b.finish(id, outcome, completedAt)
}
func (b *Bucket) finish(id, outcome string, now time.Time) {
	m, ok := b.Members[id]
	if !ok || m.Generation != b.Generation || m.Outcome != "pending" {
		return
	}
	m.Outcome = outcome
	b.Members[id] = m
	if outcome == "failure" && b.Limit.Algorithm == "brute-force" {
		b.ExpiresAt = now.Add(b.Limit.Lockout)
		b.BlockedUntil = b.ExpiresAt
	}
	if outcome != "failure" && b.Limit.Algorithm == "token-bucket" {
		b.Tokens = math.Min(float64(b.Limit.Capacity), b.Tokens+1)
	}
	if outcome == "success" && b.Limit.Algorithm == "brute-force" {
		for id, prior := range b.Members {
			if prior.Generation == m.Generation && prior.Sequence <= m.Sequence {
				delete(b.Members, id)
			}
		}
	}
	// Settled refunded work and token-bucket outcomes need no sequence history.
	if outcome != "failure" || b.Limit.Algorithm == "token-bucket" {
		delete(b.Members, id)
	}
}
func Match(k store.ProtectionKey, f store.ProtectionFilter) bool {
	return (f.Kind == "" || f.Kind == k.Kind) && (f.ConnectionID == "" || f.ConnectionID == k.ConnectionID) && (f.Identifier == "" || f.Identifier == k.Identifier) && (f.IP == "" || f.IP == k.IP)
}
