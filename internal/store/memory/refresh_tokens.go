package memory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type refreshTokens struct{ s *Store }

// taken reports whether t's ID or TokenHash is used. Called with the lock held.
func (r refreshTokens) taken(t *store.RefreshToken) bool {
	if _, ok := r.s.refreshTokens[key{t.TenantID, t.ID}]; ok {
		return true
	}
	_, ok := r.findByHash(t.TenantID, t.TokenHash)
	return ok
}

// findByHash is called with the lock held.
func (r refreshTokens) findByHash(tenantID, hash string) (*store.RefreshToken, bool) {
	for k, t := range r.s.refreshTokens {
		if k.tenant == tenantID && t.TokenHash == hash {
			return t, true
		}
	}
	return nil, false
}

func (r refreshTokens) Create(_ context.Context, t *store.RefreshToken) error {
	r.s.lock()
	defer r.s.unlock()
	if r.taken(t) {
		return store.ErrConflict
	}
	r.s.refreshTokens[key{t.TenantID, t.ID}] = cloneRefreshToken(t)
	return nil
}

func (r refreshTokens) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.RefreshToken, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	t, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRefreshToken(t), nil
}

func (r refreshTokens) Get(_ context.Context, tenantID, id string) (*store.RefreshToken, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	t, ok := r.s.refreshTokens[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRefreshToken(t), nil
}

func (r refreshTokens) ListByUser(_ context.Context, tenantID, userID string) ([]*store.RefreshToken, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var out []*store.RefreshToken
	for k, t := range r.s.refreshTokens {
		if k.tenant == tenantID && t.UserID == userID && t.RevokedAt == nil && t.RotatedAt == nil {
			out = append(out, cloneRefreshToken(t))
		}
	}
	slices.SortFunc(out, func(a, b *store.RefreshToken) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.ID, a.ID))
	})
	return out, nil
}

func (r refreshTokens) Revoke(_ context.Context, tenantID, id string, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	t, ok := r.s.refreshTokens[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	if t.RevokedAt == nil {
		v := at
		t.RevokedAt = &v
	}
	return nil
}

func (r refreshTokens) Rotate(_ context.Context, tenantID, oldID string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	r.s.lock()
	defer r.s.unlock()
	old, ok := r.s.refreshTokens[key{tenantID, oldID}]
	if !ok || (old.RevokedAt != nil && old.RotatedAt == nil) {
		return store.ErrNotFound
	}
	if old.RevokedAt != nil {
		// A rotated token of a revoked family: reuse, whatever the leeway.
		return store.ErrAlreadyUsed
	}
	if next.TenantID != tenantID || next.FamilyID != old.FamilyID || r.taken(next) {
		return store.ErrConflict
	}
	if old.RotatedAt != nil {
		if leeway <= 0 || !at.Before(old.RotatedAt.Add(leeway)) {
			r.revokeFamily(tenantID, old.FamilyID, at)
			return store.ErrAlreadyUsed
		}
	} else {
		t := at
		old.RotatedAt = &t
	}
	r.s.refreshTokens[key{next.TenantID, next.ID}] = cloneRefreshToken(next)
	return nil
}

func (r refreshTokens) Touch(_ context.Context, tenantID, id string, idleExpiresAt time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	t, ok := r.s.refreshTokens[key{tenantID, id}]
	if !ok || t.RevokedAt != nil || t.RotatedAt != nil {
		return store.ErrNotFound
	}
	t.IdleExpiresAt = idleExpiresAt
	return nil
}

func (r refreshTokens) RevokeFamily(_ context.Context, tenantID, familyID string, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	r.revokeFamily(tenantID, familyID, at)
	return nil
}

func (r refreshTokens) RevokeByUser(_ context.Context, tenantID, userID string, at time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, t := range r.s.refreshTokens {
		if k.tenant == tenantID && t.UserID == userID && t.RevokedAt == nil {
			v := at
			t.RevokedAt = &v
			n++
		}
	}
	return n, nil
}

// revokeFamily is called with the lock held.
func (r refreshTokens) revokeFamily(tenantID, familyID string, at time.Time) {
	for k, t := range r.s.refreshTokens {
		if k.tenant == tenantID && t.FamilyID == familyID && t.RevokedAt == nil {
			v := at
			t.RevokedAt = &v
		}
	}
}

func (r refreshTokens) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, t := range r.s.refreshTokens {
		if (!t.ExpiresAt.IsZero() && !t.ExpiresAt.After(before)) ||
			(!t.IdleExpiresAt.IsZero() && !t.IdleExpiresAt.After(before)) {
			delete(r.s.refreshTokens, k)
			n++
		}
	}
	return n, nil
}
