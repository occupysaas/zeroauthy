package memory

import (
	"cmp"
	"context"
	"maps"
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

// insert copies its input. Sequence order, independent of clocks or random IDs,
// makes the newest live sibling deterministic even after another sibling is revoked.
func (r refreshTokens) insert(t *store.RefreshToken, parentID string) {
	k := key{t.TenantID, t.ID}
	row := cloneRefreshToken(t)
	if row.Access == "" {
		row.Access = "offline"
	}
	row.ParentID = parentID
	r.s.refreshTokens[k] = row
	r.s.refreshSequence++
	r.s.refreshOrder[k] = r.s.refreshSequence
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
	if r.taken(t) || r.s.refreshFamilyAliases[key{t.TenantID, t.FamilyID}] != "" {
		return store.ErrConflict
	}
	r.insert(t, t.ParentID)
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
		if k.tenant == tenantID && t.UserID == userID && t.RevokedAt == nil && t.RotatedAt == nil && t.Access != "online" {
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
	if !old.ValidSuccessor(next) || next.FamilyID != old.FamilyID || r.taken(next) {
		return store.ErrConflict
	}
	if err := r.checkRotation(old, at, leeway); err != nil {
		return err
	}
	if old.RotatedAt == nil {
		old.RotatedAt = &at
	}
	r.insert(next, oldID)
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
	if current := r.s.refreshFamilyAliases[key{tenantID, familyID}]; current != "" {
		familyID = current
	}
	r.revokeFamily(tenantID, familyID, at)
	return nil
}

func (r refreshTokens) RevokeByUser(_ context.Context, tenantID, userID string, at time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	return r.revokeMatching(tenantID, at, func(t *store.RefreshToken) bool { return t.UserID == userID }), nil
}

// revokeFamily is called with the lock held.
func (r refreshTokens) revokeFamily(tenantID, familyID string, at time.Time) {
	r.revokeMatching(tenantID, at, func(t *store.RefreshToken) bool { return t.FamilyID == familyID })
}

func (r refreshTokens) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	retained := make(map[key]bool)
	for k, t := range r.s.refreshTokens {
		if expiredToken(t, before) {
			delete(r.s.refreshTokens, k)
			delete(r.s.refreshOrder, k)
			n++
		} else {
			retained[key{k.tenant, t.FamilyID}] = true
		}
	}
	maps.DeleteFunc(r.s.refreshFamilyAliases, func(k key, current string) bool {
		return !retained[key{k.tenant, current}]
	})
	return n, nil
}

func expiredToken(t *store.RefreshToken, at time.Time) bool {
	return (!t.ExpiresAt.IsZero() && !at.Before(t.ExpiresAt)) ||
		(!t.IdleExpiresAt.IsZero() && !at.Before(t.IdleExpiresAt))
}

// checkRotation is called with the lock held. A failed reuse check commits
// the family revocation even though the successor is refused.
func (r refreshTokens) checkRotation(old *store.RefreshToken, at time.Time, leeway time.Duration) error {
	if old.RotatedAt == nil {
		return nil
	}
	if leeway > 0 && at.Before(old.RotatedAt.Add(leeway)) {
		var newest *store.RefreshToken
		var sequence uint64
		for k, t := range r.s.refreshTokens {
			if k.tenant != old.TenantID || t.FamilyID != old.FamilyID || t.RevokedAt != nil || t.RotatedAt != nil || expiredToken(t, at) {
				continue
			}
			if n := r.s.refreshOrder[k]; n > sequence {
				newest, sequence = t, n
			}
		}
		if newest != nil && newest.ParentID == old.ID {
			return nil
		}
	}
	r.revokeFamily(old.TenantID, old.FamilyID, at)
	return store.ErrAlreadyUsed
}

func (r refreshTokens) CheckRotation(_ context.Context, tid, id string, at time.Time, leeway time.Duration) error {
	r.s.lock()
	defer r.s.unlock()
	old := r.s.refreshTokens[key{tid, id}]
	if old == nil || !old.Rotating || (old.RevokedAt != nil && old.RotatedAt == nil) {
		return store.ErrNotFound
	}
	if old.RevokedAt != nil {
		return store.ErrAlreadyUsed
	}
	return r.checkRotation(old, at, leeway)
}

func (r refreshTokens) ConvertNonRotating(_ context.Context, tid, presentedID string, next *store.RefreshToken) error {
	if next == nil {
		return store.ErrInvalid
	}
	return r.convert(tid, presentedID, next, false, next.CreatedAt, 0)
}

func (r refreshTokens) ConvertRotating(_ context.Context, tid, presentedID string, next *store.RefreshToken, at time.Time, leeway time.Duration) error {
	return r.convert(tid, presentedID, next, true, at, leeway)
}

func (r refreshTokens) convert(tid, id string, next *store.RefreshToken, rotating bool, at time.Time, leeway time.Duration) error {
	r.s.lock()
	defer r.s.unlock()
	old := r.s.refreshTokens[key{tid, id}]
	if old == nil || old.Rotating != rotating || old.Access == "online" || expiredToken(old, at) {
		return store.ErrNotFound
	}
	if old.RevokedAt != nil {
		if old.RotatedAt != nil {
			return store.ErrAlreadyUsed
		}
		return store.ErrNotFound
	}
	if !old.ValidSuccessor(next) || next.Rotating == rotating || r.taken(next) {
		return store.ErrConflict
	}
	if next.FamilyID == "" {
		return store.ErrInvalid
	}
	if r.s.refreshFamilyAliases[key{tid, next.FamilyID}] != "" {
		return store.ErrConflict
	}
	for k, t := range r.s.refreshTokens {
		if k.tenant == tid && t.FamilyID == next.FamilyID {
			return store.ErrConflict
		}
	}
	if rotating {
		if err := r.checkRotation(old, at, leeway); err != nil {
			return err
		}
	}
	for k, t := range r.s.refreshTokens {
		if k.tenant != tid || t.ClientID != old.ClientID || t.UserID != old.UserID || t.Audience != old.Audience || t.Rotating != rotating || t.Access == "online" {
			continue
		}
		if !rotating {
			delete(r.s.refreshTokens, k)
			delete(r.s.refreshOrder, k)
		} else if t.RevokedAt == nil {
			t.RevokedAt = &at
		}
	}
	// Preserve every earlier revocation handle even when its source row was
	// deleted. Only the presented family's aliases follow this conversion.
	for k, current := range r.s.refreshFamilyAliases {
		if k.tenant == tid && current == old.FamilyID {
			r.s.refreshFamilyAliases[k] = next.FamilyID
		}
	}
	r.s.refreshFamilyAliases[key{tid, old.FamilyID}] = next.FamilyID
	r.insert(next, "")
	return nil
}

func (r refreshTokens) RevokeByUserClient(_ context.Context, tid, userID, clientID, audience string, at time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	return r.revokeMatching(tid, at, func(t *store.RefreshToken) bool {
		if t.UserID != userID || t.ClientID != clientID {
			return false
		}
		return audience == "" || r.matchesAudience(t, audience)
	}), nil
}
func (r refreshTokens) RevokeBySession(_ context.Context, tid, sessionID string, at time.Time) (int, error) {
	if sessionID == "" {
		return 0, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	return r.revokeMatching(tid, at, func(t *store.RefreshToken) bool { return t.SessionID == sessionID }), nil
}

func (r refreshTokens) SessionOwners(_ context.Context, tid, sessionID string) ([]string, error) {
	if sessionID == "" {
		return nil, store.ErrInvalid
	}
	r.s.readLock()
	defer r.s.readUnlock()
	owners := map[string]bool{}
	for k, t := range r.s.refreshTokens {
		if k.tenant == tid && t.SessionID == sessionID && t.RevokedAt == nil && t.UserID != "" {
			owners[t.UserID] = true
		}
	}
	return slices.Sorted(maps.Keys(owners)), nil
}
func (r refreshTokens) revokeMatching(tid string, at time.Time, matches func(*store.RefreshToken) bool) int {
	n := 0
	for k, t := range r.s.refreshTokens {
		if k.tenant == tid && t.RevokedAt == nil && matches(t) {
			t.RevokedAt = &at
			n++
		}
	}
	return n
}

func (r refreshTokens) ListByUserPage(_ context.Context, tid, userID, clientID, from string, take int) ([]*store.RefreshToken, string, error) {
	if take < 1 || take > 100 {
		return nil, "", store.ErrInvalid
	}
	r.s.readLock()
	defer r.s.readUnlock()
	var ids []string
	for k, t := range r.s.refreshTokens {
		if k.tenant == tid && t.UserID == userID && (clientID == "" || t.ClientID == clientID) && t.ID > from && t.RotatedAt == nil && t.RevokedAt == nil && t.Access != "online" {
			ids = append(ids, t.ID)
		}
	}
	slices.Sort(ids)
	next := ""
	if len(ids) > take {
		ids = ids[:take]
		next = ids[take-1]
	}
	out := make([]*store.RefreshToken, len(ids))
	for i, id := range ids {
		out[i] = cloneRefreshToken(r.s.refreshTokens[key{tid, id}])
	}
	return out, next, nil
}
func (r refreshTokens) UpdateMetadata(_ context.Context, tid, id string, md map[string]string) (*store.RefreshToken, error) {
	r.s.lock()
	defer r.s.unlock()
	t := r.s.refreshTokens[key{tid, id}]
	if t == nil || t.Access == "online" {
		return nil, store.ErrNotFound
	}
	t.Metadata = maps.Clone(md)
	return cloneRefreshToken(t), nil
}
func (r refreshTokens) RecordExchange(_ context.Context, tid, id, ip, ua string, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	t := r.s.refreshTokens[key{tid, id}]
	if t == nil || t.RevokedAt != nil {
		return store.ErrNotFound
	}
	if t.Device == nil {
		t.Device = &store.RefreshTokenDevice{}
	}
	t.Device.LastIP, t.Device.LastUserAgent = ip, ua
	t.LastExchangedAt = &at
	return nil
}

func (r refreshTokens) RevokeOfflineByUser(_ context.Context, tid, user, client string, audience *string, at time.Time) (int, error) {
	if user == "" {
		return 0, store.ErrInvalid
	}
	r.s.lock()
	defer r.s.unlock()
	return r.revokeMatching(tid, at, func(t *store.RefreshToken) bool {
		return t.Access != "online" && t.UserID == user && (client == "" || t.ClientID == client) && (audience == nil || r.matchesAudience(t, *audience))
	}), nil
}

func (r refreshTokens) matchesAudience(t *store.RefreshToken, audience string) bool {
	if t.Audience == audience {
		return true
	}
	origin := t.Origin
	if tn := r.s.tenants[t.TenantID]; origin == "" && tn != nil && tn.CanonicalHost != "" {
		origin = "https://" + tn.CanonicalHost
	}
	return t.Audience == "" && origin != "" && audience == origin+"/userinfo"
}
