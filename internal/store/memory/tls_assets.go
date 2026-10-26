package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type tlsAssets struct{ s *Store }

func (s *Store) TLSAssets() store.TLSAssets { return tlsAssets{s} }
func (r tlsAssets) Get(_ context.Context, key string) (*store.TLSAsset, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	a := r.s.tlsAssets[key]
	if a == nil {
		return nil, store.ErrNotFound
	}
	return a.Clone(), nil
}
func (r tlsAssets) Put(_ context.Context, a *store.TLSAsset, expected int64) error {
	if a == nil || a.Key == "" || expected < 0 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.tlsAssets[a.Key]
	if old == nil && expected != 0 {
		return store.ErrNotFound
	}
	if old != nil && old.Revision != expected {
		return store.ErrConflict
	}
	c := a.Clone()
	c.Revision = expected + 1
	r.s.tlsAssets[a.Key] = c
	a.Revision = c.Revision
	return nil
}
func (r tlsAssets) Delete(_ context.Context, key string, expected int64) error {
	if expected < 1 {
		return store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.tlsAssets[key]
	if old == nil {
		return store.ErrNotFound
	}
	if old.Revision != expected {
		return store.ErrConflict
	}
	delete(r.s.tlsAssets, key)
	return nil
}
func (r tlsAssets) ListExpired(_ context.Context, limit int) ([]*store.TLSAsset, error) {
	if limit < 1 {
		return nil, store.ErrInvalid
	}
	r.s.readLock()
	defer r.s.readUnlock()
	now := r.s.now()
	out := []*store.TLSAsset{}
	for _, a := range r.s.tlsAssets {
		if !a.ExpiresAt.IsZero() && !now.Before(a.ExpiresAt) {
			out = append(out, a.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *store.TLSAsset) int { return cmp.Compare(a.Key, b.Key) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (r tlsAssets) ClaimLease(_ context.Context, key, owner string, duration time.Duration) (*store.TLSLease, error) {
	if key == "" || owner == "" || duration <= 0 {
		return nil, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	old := r.s.tlsLeases[key]
	now := r.s.now()
	if old != nil && now.Before(old.Until) {
		return nil, store.ErrConflict
	}
	fence := int64(1)
	if old != nil {
		fence = old.Fence + 1
	}
	l := &store.TLSLease{Key: key, Owner: owner, Fence: fence, Until: now.Add(duration)}
	r.s.tlsLeases[key] = l
	c := *l
	return &c, nil
}
func (r tlsAssets) valid(l store.TLSLease) bool {
	old := r.s.tlsLeases[l.Key]
	return old != nil && old.Owner == l.Owner && old.Fence == l.Fence && r.s.now().Before(old.Until)
}
func (r tlsAssets) RenewLease(_ context.Context, l store.TLSLease, duration time.Duration) (*store.TLSLease, error) {
	if duration <= 0 {
		return nil, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	if !r.valid(l) {
		return nil, store.ErrConflict
	}
	old := r.s.tlsLeases[l.Key]
	old.Until = r.s.now().Add(duration)
	c := *old
	return &c, nil
}
func (r tlsAssets) CheckLease(_ context.Context, l store.TLSLease) error {
	r.s.lock()
	defer r.s.unlock()
	if !r.valid(l) {
		return store.ErrConflict
	}
	if r.s.tx {
		r.s.checkedLeases[l.Key] = l
	}
	return nil
}
func (r tlsAssets) ReleaseLease(_ context.Context, l store.TLSLease) error {
	r.s.lock()
	defer r.s.unlock()
	if !r.valid(l) {
		return store.ErrConflict
	}
	old := r.s.tlsLeases[l.Key]
	old.Owner = ""
	old.Until = time.Time{}
	return nil
}

// Keep fence history when cascades revoke outstanding work.
func (s *Store) expireLease(key string) {
	if l := s.tlsLeases[key]; l != nil {
		l.Owner = ""
		l.Until = time.Time{}
	}
}
