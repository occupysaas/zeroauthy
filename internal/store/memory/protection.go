package memory

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/protectionstate"
	"time"
)

type protection struct{ s *Store }

func (s *Store) Protection() store.Protection { return protection{s} }
func (r protection) state(tenant string) (*protectionstate.State, error) {
	if r.s.tenants[tenant] == nil {
		return nil, store.ErrNotFound
	}
	p := r.s.protection[tenant]
	if p == nil {
		p = protectionstate.NewState()
		r.s.protection[tenant] = p
	}
	return p, nil
}
func (r protection) Reserve(_ context.Context, ls []store.ProtectionLimit, now time.Time) (store.ProtectionAdmission, error) {
	if err := protectionstate.Validate(ls); err != nil {
		return store.ProtectionAdmission{}, err
	}
	if len(ls) == 0 {
		return store.ProtectionAdmission{Allowed: true}, nil
	}
	ids := make([]string, len(ls))
	for i, l := range ls {
		ids[i] = protectionstate.ID(l.Key)
	}
	id, gen := protectionstate.NewID(), protectionstate.NewID()
	r.s.lock()
	defer r.s.unlock()
	p, err := r.state(ls[0].Key.TenantID)
	if err != nil {
		return store.ProtectionAdmission{}, err
	}
	return p.Reserve(ls, ids, id, gen, now), nil
}
func (r protection) Complete(_ context.Context, receipt store.ProtectionReceipt, outcome string, now time.Time) error {
	if outcome != "failure" && outcome != "success" && outcome != "refund" {
		return store.ErrInvalid
	}
	if receipt.ID == "" {
		return nil
	}
	r.s.lock()
	defer r.s.unlock()
	p, err := r.state(receipt.TenantID)
	if err != nil {
		return err
	}
	p.Complete(receipt.ID, outcome, now)
	return nil
}
func (r protection) Blocks(_ context.Context, tenant string, f store.ProtectionFilter, now time.Time) ([]store.ProtectionBlock, error) {
	r.s.lock()
	defer r.s.unlock()
	p, e := r.state(tenant)
	if e != nil {
		return nil, e
	}
	return p.Blocks(f, now), nil
}
func (r protection) Clear(_ context.Context, tenant string, f store.ProtectionFilter) error {
	r.s.lock()
	defer r.s.unlock()
	p, e := r.state(tenant)
	if e != nil {
		return e
	}
	p.Clear(f)
	return nil
}
func (r protection) UseProof(_ context.Context, hash string, now, expires time.Time) (bool, error) {
	if hash == "" || !expires.After(now) {
		return false, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if until, ok := r.s.proofs[hash]; ok && now.Before(until) {
		return false, nil
	}
	r.s.proofs[hash] = expires
	return true, nil
}
func (r protection) RecordRisk(_ context.Context, tenant, id, ip string, now time.Time) error {
	if id == "" || ip == "" {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	p, e := r.state(tenant)
	if e != nil {
		return e
	}
	p.RecordRisk(id, ip, now)
	return nil
}
func (r protection) RiskCount(_ context.Context, tenant, ip string, now time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	p, e := r.state(tenant)
	if e != nil {
		return 0, e
	}
	return p.RiskCount(ip, now), nil
}
func (r protection) Sweep(_ context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for _, p := range r.s.protection {
		n += p.Sweep(now, limit-n)
		if n >= limit {
			return n, nil
		}
	}
	for id, expiry := range r.s.proofs {
		if n >= limit {
			break
		}
		if !now.Before(expiry) {
			delete(r.s.proofs, id)
			n++
		}
	}
	return n, nil
}
