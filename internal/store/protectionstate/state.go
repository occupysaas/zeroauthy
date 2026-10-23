package protectionstate

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"sort"
	"time"
)

type Receipt struct {
	ID                    string
	ReservedAt, ExpiresAt time.Time
	Completed             bool
	Outcome               string
}
type Risk struct {
	IP         string
	OccurredAt time.Time
}

// State contains one tenant's state. Proof replay is deliberately stored separately.
type State struct {
	Buckets  map[string]*Bucket
	Receipts map[string]Receipt
	Risks    map[string]Risk
}

func NewState() *State { return &State{map[string]*Bucket{}, map[string]Receipt{}, map[string]Risk{}} }
func (s *State) Clone() *State {
	c := NewState()
	for k, v := range s.Buckets {
		c.Buckets[k] = v.Clone()
	}
	for k, v := range s.Receipts {
		c.Receipts[k] = v
	}
	for k, v := range s.Risks {
		c.Risks[k] = v
	}
	return c
}

// Reserve receives precomputed opaque IDs, keeping hashing and entropy outside locks.
func (s *State) Reserve(ls []store.ProtectionLimit, ids []string, receipt, generation string, now time.Time) store.ProtectionAdmission {
	a := store.ProtectionAdmission{Allowed: true}
	bs := make([]*Bucket, len(ls))
	expires := now.Add(PendingLifetime)
	for i, l := range ls {
		b := s.Buckets[ids[i]]
		if b == nil || !now.Before(b.ExpiresAt) || !b.Matches(l) {
			b = New(ids[i], generation, l, now)
		} else {
			b = b.Clone()
			b.Limit = l
		}
		b.Advance(now)
		bs[i] = b
		if retry := b.RetryAt(now); !retry.IsZero() {
			a.Allowed = false
			if retry.After(a.RetryAt) {
				a.RetryAt = retry
			}
		}
		if b.ExpiresAt.After(expires) {
			expires = b.ExpiresAt
		}
	}
	// Advance abandoned work even when the new request cannot acquire all budgets.
	for i, b := range bs {
		s.Buckets[ids[i]] = b
	}
	if !a.Allowed {
		return a
	}
	for _, b := range bs {
		b.Reserve(receipt, now)
	}
	s.Receipts[receipt] = Receipt{ID: receipt, ReservedAt: now, ExpiresAt: expires}
	a.Receipt = store.ProtectionReceipt{TenantID: ls[0].Key.TenantID, ID: receipt}
	return a
}
func (s *State) Complete(id, outcome string, now time.Time) {
	r, ok := s.Receipts[id]
	if !ok || r.Completed {
		return
	}
	if !now.Before(r.ReservedAt.Add(PendingLifetime)) {
		outcome = "failure"
	}
	for _, b := range s.Buckets {
		if now.Before(b.ExpiresAt) {
			b.Complete(id, outcome, now)
		}
	}
	r.Completed = true
	r.Outcome = outcome
	s.Receipts[id] = r
}
func (s *State) Blocks(f store.ProtectionFilter, now time.Time) []store.ProtectionBlock {
	out := []store.ProtectionBlock{}
	for _, b := range s.Buckets {
		if !now.Before(b.ExpiresAt) || !Match(b.Limit.Key, f) {
			continue
		}
		b.Advance(now)
		if retry := b.RetryAt(now); !retry.IsZero() {
			out = append(out, store.ProtectionBlock{Key: b.Limit.Key, BlockedUntil: retry})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Key, out[j].Key
		return a.Kind+a.ConnectionID+a.Identifier+a.IP < b.Kind+b.ConnectionID+b.Identifier+b.IP
	})
	return out
}
func (s *State) Clear(f store.ProtectionFilter) {
	for id, b := range s.Buckets {
		if Match(b.Limit.Key, f) {
			delete(s.Buckets, id)
		}
	}
}
func (s *State) RecordRisk(id, ip string, now time.Time) {
	if _, ok := s.Risks[id]; !ok {
		s.Risks[id] = Risk{ip, now}
	}
}
func (s *State) RiskCount(ip string, now time.Time) int {
	n := 0
	for _, r := range s.Risks {
		if r.IP == ip && !r.OccurredAt.After(now) && now.Before(r.OccurredAt.Add(15*time.Minute)) {
			n++
		}
	}
	return n
}
func (s *State) Sweep(now time.Time, limit int) int {
	n := 0
	for id, r := range s.Receipts {
		if n >= limit {
			return n
		}
		if !r.Completed && !now.Before(r.ReservedAt.Add(PendingLifetime)) {
			s.Complete(id, "failure", now)
			n++
		}
	}

	for id, b := range s.Buckets {
		if n >= limit {
			return n
		}
		if !now.Before(b.ExpiresAt) {
			delete(s.Buckets, id)
			n++
		}
	}
	for id, r := range s.Receipts {
		if n >= limit {
			return n
		}
		if !now.Before(r.ExpiresAt) {
			live := false
			for _, b := range s.Buckets {
				if _, ok := b.Members[id]; ok {
					live = true
					break
				}
			}
			if !live {
				delete(s.Receipts, id)
				n++
			}
		}
	}
	for id, r := range s.Risks {
		if n >= limit {
			return n
		}
		if !now.Before(r.OccurredAt.Add(15 * time.Minute)) {
			delete(s.Risks, id)
			n++
		}
	}
	return n
}
