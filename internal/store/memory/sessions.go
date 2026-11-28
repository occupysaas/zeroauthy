package memory

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type sessions struct{ s *Store }

func (r sessions) Create(_ context.Context, s *store.LoginSession) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{s.TenantID, s.ID}
	if _, ok := r.s.sessions[k]; ok {
		return store.ErrConflict
	}
	if _, ok := r.findByHash(s.TenantID, s.TokenHash); ok {
		return store.ErrConflict
	}
	r.s.sessions[k] = cloneSession(s)
	return nil
}

func (r sessions) GetByTokenHash(_ context.Context, tenantID, tokenHash string) (*store.LoginSession, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	s, ok := r.findByHash(tenantID, tokenHash)
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSession(s), nil
}

func (r sessions) Get(_ context.Context, tenantID, id string) (*store.LoginSession, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSession(s), nil
}

// WithTx holds the memory store's write lock for its entire callback.
func (r sessions) GetForUpdate(ctx context.Context, tenantID, id string) (*store.LoginSession, error) {
	return r.Get(ctx, tenantID, id)
}

func (r sessions) ListByUser(_ context.Context, tenantID, userID string) ([]*store.LoginSession, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var out []*store.LoginSession
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.UserID == userID {
			out = append(out, cloneSession(s))
		}
	}
	slices.SortFunc(out, func(a, b *store.LoginSession) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), cmp.Compare(b.ID, a.ID))
	})
	return out, nil
}

func (r sessions) Touch(_ context.Context, tenantID, id string, at, idleExpiresAt time.Time, ip, userAgent string) error {
	r.s.lock()
	defer r.s.unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	s.IdleExpiresAt = idleExpiresAt
	s.UpdatedAt, s.LastInteractedAt = at, at
	s.LastIP, s.LastUserAgent = ip, userAgent
	return nil
}

func (r sessions) AddClient(_ context.Context, tenantID, id, clientID string) error {
	r.s.lock()
	defer r.s.unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	if !slices.Contains(s.ClientIDs, clientID) {
		s.ClientIDs = append(slices.Clone(s.ClientIDs), clientID)
	}
	return nil
}

func (r sessions) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, s := range r.s.sessions {
		if !s.ExpiresAt.After(before) || !s.IdleExpiresAt.After(before) {
			delete(r.s.sessions, k)
			n++
		}
	}
	return n, nil
}

func (r sessions) DeleteByUser(_ context.Context, tenantID, userID string) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.UserID == userID {
			delete(r.s.sessions, k)
			n++
		}
	}
	return n, nil
}

func (r sessions) Delete(_ context.Context, tenantID, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tenantID, id}
	if _, ok := r.s.sessions[k]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.sessions, k)
	return nil
}

// findByHash is called with the lock held.
func (r sessions) findByHash(tenantID, hash string) (*store.LoginSession, bool) {
	for k, s := range r.s.sessions {
		if k.tenant == tenantID && s.TokenHash == hash {
			return s, true
		}
	}
	return nil, false
}

func (r sessions) MarkMFA(_ context.Context, tid, id string, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	v := r.s.sessions[key{tid, id}]
	if v == nil {
		return store.ErrNotFound
	}
	v.MFAAt = at
	return nil
}

func (r sessions) AddMethod(_ context.Context, tid, id string, method store.AuthMethod) error {
	r.s.lock()
	defer r.s.unlock()
	s := r.s.sessions[key{tid, id}]
	if s == nil {
		return store.ErrNotFound
	}
	s.AuthMethods = append(s.AuthMethods, method)
	return nil
}

func (r sessions) UpdateMetadata(_ context.Context, tid, id string, md map[string]string) (*store.LoginSession, error) {
	r.s.lock()
	defer r.s.unlock()
	s := r.s.sessions[key{tid, id}]
	if s == nil {
		return nil, store.ErrNotFound
	}
	s.Metadata = maps.Clone(md)
	return cloneSession(s), nil
}

// SetLimits sets the session's expiries and cookie mode (Plan 40).
func (r sessions) SetLimits(_ context.Context, tid, id string, expiresAt, idleExpiresAt time.Time, cookieMode string) (*store.LoginSession, error) {
	r.s.lock()
	defer r.s.unlock()
	s := r.s.sessions[key{tid, id}]
	if s == nil {
		return nil, store.ErrNotFound
	}
	s.ExpiresAt, s.IdleExpiresAt, s.CookieMode = expiresAt, idleExpiresAt, cookieMode
	return cloneSession(s), nil
}

func (r sessions) ListExpired(_ context.Context, before time.Time, limit int) ([]*store.LoginSession, error) {
	if limit < 1 || limit > 1000 {
		return nil, store.ErrInvalid
	}
	r.s.readLock()
	defer r.s.readUnlock()
	out := []*store.LoginSession{}
	for _, s := range r.s.sessions {
		if !s.ExpiresAt.After(before) || !s.IdleExpiresAt.After(before) {
			out = append(out, cloneSession(s))
		}
	}
	slices.SortFunc(out, func(a, b *store.LoginSession) int {
		if a.TenantID < b.TenantID {
			return -1
		}
		if a.TenantID > b.TenantID {
			return 1
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out[:min(len(out), limit)], nil
}

func (r sessions) RecordClientOrganization(_ context.Context, tenantID, id, clientID, orgID string) error {
	r.s.lock()
	defer r.s.unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	if !slices.Contains(s.ClientIDs, clientID) {
		s.ClientIDs = append(slices.Clone(s.ClientIDs), clientID)
	}
	if s.ClientOrganizations == nil {
		s.ClientOrganizations = map[string]string{}
	}
	s.ClientOrganizations[clientID] = orgID
	return nil
}

// RecordSAMLParticipant implements store.SAMLSessionRecorder.
func (r sessions) RecordSAMLParticipant(_ context.Context, tenantID, id string, p store.SAMLParticipant) error {
	r.s.lock()
	defer r.s.unlock()
	s, ok := r.s.sessions[key{tenantID, id}]
	if !ok {
		return store.ErrNotFound
	}
	if p.ClientID != "" && !slices.Contains(s.ClientIDs, p.ClientID) {
		s.ClientIDs = append(slices.Clone(s.ClientIDs), p.ClientID)
	}
	s.SAMLParticipants = store.UpsertSAMLParticipant(s.SAMLParticipants, p)
	return nil
}

func (r sessions) SetClaims(_ context.Context, tid, id, client, raw string) (*store.LoginSession, error) {
	if err := store.ValidateSessionClaims(raw); err != nil {
		return nil, err
	}
	r.s.lock()
	defer r.s.unlock()
	s, ok := r.s.sessions[key{tid, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if s.UserinfoClaims == nil {
		s.UserinfoClaims = map[string]string{}
	}
	s.UserinfoClaims[client] = raw
	return cloneSession(s), nil
}
