package memory

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// fedKey is store.FederatedIdentityKey as a map key.
type fedKey = store.FederatedIdentityKey

type federation struct{ s *Store }

func (s *Store) Federation() store.Federation { return federation{s} }

func (r federation) IdentityEpoch(_ context.Context, tenantID string) (int64, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	t, ok := r.s.tenants[tenantID]
	if !ok {
		return 0, store.ErrNotFound
	}
	return t.IdentityEpoch, nil
}

func (r federation) BumpIdentityEpoch(_ context.Context, tenantID string) error {
	r.s.lock()
	defer r.s.unlock()
	return r.s.bumpEpoch(tenantID)
}

// bumpEpoch is called with the lock held.
func (s *Store) bumpEpoch(tenantID string) error {
	t, ok := s.tenants[tenantID]
	if !ok {
		return store.ErrNotFound
	}
	t.IdentityEpoch++
	return nil
}

func (r federation) CreateAttempt(_ context.Context, a *store.FederationAttempt) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{a.TenantID, a.StateHash}
	if _, ok := r.s.fedAttempts[k]; ok {
		return store.ErrConflict
	}
	for ok, o := range r.s.fedAttempts {
		if ok.tenant == a.TenantID && o.TransactionID == a.TransactionID {
			o.Superseded = true
		}
	}
	n := a.Clone()
	n.Status, n.Superseded = store.AttemptPending, false
	r.s.fedAttempts[k] = n
	return nil
}

func (r federation) GetAttempt(_ context.Context, tenantID, stateHash string) (*store.FederationAttempt, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	a, ok := r.s.fedAttempts[key{tenantID, stateHash}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return a.Clone(), nil
}

func (r federation) ClaimAttempt(_ context.Context, tenantID, stateHash, cookieHash, origin string, now time.Time) (*store.FederationAttempt, error) {
	r.s.lock()
	defer r.s.unlock()
	a, ok := r.s.fedAttempts[key{tenantID, stateHash}]
	switch {
	case !ok || a.Superseded || !now.Before(a.ExpiresAt):
		return nil, store.ErrNotFound
	case a.Status != store.AttemptPending:
		return nil, store.ErrAlreadyUsed
	case a.CookieHash != cookieHash || a.Origin != origin:
		return nil, store.ErrInvalid
	}
	a.Status = store.AttemptClaimed
	return a.Clone(), nil
}

func (r federation) FinishAttempt(_ context.Context, tenantID, stateHash string) error {
	r.s.lock()
	defer r.s.unlock()
	a, ok := r.s.fedAttempts[key{tenantID, stateHash}]
	if !ok {
		return store.ErrNotFound
	}
	if a.Status != store.AttemptClaimed || a.Superseded {
		return store.ErrAlreadyUsed
	}
	a.Status = store.AttemptFinished
	return nil
}

func (r federation) PutIdentity(_ context.Context, k store.FederatedIdentityKey, userID string) error {
	r.s.lock()
	defer r.s.unlock()
	return r.s.putIdentity(k, userID)
}

// putIdentity is called with the lock held.
func (s *Store) putIdentity(k fedKey, userID string) error {
	if owner, ok := s.fedIdentities[k]; ok && owner != userID {
		return store.ErrConflict
	}
	s.fedIdentities[k] = userID
	return nil
}

func (r federation) DeleteIdentity(_ context.Context, k store.FederatedIdentityKey, expectedUserID string) error {
	r.s.lock()
	defer r.s.unlock()
	owner, ok := r.s.fedIdentities[k]
	switch {
	case !ok:
		return store.ErrNotFound
	case owner != expectedUserID:
		return store.ErrConflict
	}
	delete(r.s.fedIdentities, k)
	return r.s.bumpEpoch(k.TenantID)
}

func (r federation) GetTokens(_ context.Context, k store.FederatedIdentityKey) ([]byte, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	b, ok := r.s.fedTokens[k]
	if !ok {
		return nil, store.ErrNotFound
	}
	return bytes.Clone(b), nil
}

func (r federation) PutTokens(_ context.Context, k store.FederatedIdentityKey, sealed []byte) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.tenants[k.TenantID]; !ok {
		return store.ErrNotFound
	}
	r.s.fedTokens[k] = bytes.Clone(sealed)
	return nil
}

func (r federation) DeleteTokens(_ context.Context, k store.FederatedIdentityKey) error {
	r.s.lock()
	defer r.s.unlock()
	delete(r.s.fedTokens, k)
	return nil
}

func (r federation) DeleteExpired(_ context.Context, before time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, a := range r.s.fedAttempts {
		if a.ExpiresAt.Before(before) {
			delete(r.s.fedAttempts, k)
			n++
		}
	}
	return n, nil
}

func (r users) FindByIdentity(_ context.Context, tenantID, connectionID, subject string) (*store.User, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	owner, ok := r.s.fedIdentities[fedKey{TenantID: tenantID, ConnectionID: connectionID, Subject: subject}]
	if !ok {
		return nil, store.ErrNotFound
	}
	u, ok := r.s.users[key{tenantID, owner}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

// federatedKeys resolves u's federated identities with the lock held.
func (s *Store) federatedKeys(u *store.User) ([]fedKey, error) {
	return store.ResolveFederatedKeys(u, func(name string) (*store.Connection, error) {
		for k, c := range s.connections {
			if k.tenant == u.TenantID && c.Name == name {
				return c, nil
			}
		}
		return nil, store.ErrNotFound
	})
}

// checkIdentities reports ErrConflict if another user owns one of want, with
// the lock held. It changes nothing, so callers check before writing.
func (s *Store) checkIdentities(userID string, want []fedKey) error {
	for _, k := range want {
		if owner, ok := s.fedIdentities[k]; ok && owner != userID {
			return store.ErrConflict
		}
	}
	return nil
}

// syncIdentities brings the index entries of userID to want, with the lock
// held, after checkIdentities passed. Removing an entry bumps the tenant's
// identity epoch; token records stay with the identity key for its next owner.
func (s *Store) syncIdentities(tenantID, userID string, want []fedKey) error {
	removed := false
	for k, owner := range s.fedIdentities {
		if k.TenantID == tenantID && owner == userID && !slices.Contains(want, k) {
			delete(s.fedIdentities, k)
			removed = true
		}
	}
	for _, k := range want {
		if err := s.putIdentity(k, userID); err != nil {
			return err
		}
	}
	if removed {
		return s.bumpEpoch(tenantID)
	}
	return nil
}

// dropFederation removes the index entries and token records of the users in
// gone and bumps the epoch when anyone was deleted, with the lock held. The
// tenant may already be gone (tenant deletion), which needs no bump.
func (s *Store) dropFederation(tenantID string, gone map[string]bool) {
	if len(gone) == 0 {
		return
	}
	for k, owner := range s.fedIdentities {
		if k.TenantID == tenantID && gone[owner] {
			delete(s.fedIdentities, k)
			delete(s.fedTokens, k)
		}
	}
	_ = s.bumpEpoch(tenantID)
}

// dropConnectionFederation removes every index entry and token record of a
// connection, with the lock held.
func (s *Store) dropConnectionFederation(tenantID, connectionID string) {
	for k := range s.fedIdentities {
		if k.TenantID == tenantID && k.ConnectionID == connectionID {
			delete(s.fedIdentities, k)
		}
	}
	for k := range s.fedTokens {
		if k.TenantID == tenantID && k.ConnectionID == connectionID {
			delete(s.fedTokens, k)
		}
	}
}

// dropTenantFederation removes all federation state of a tenant, with the
// lock held.
func (s *Store) dropTenantFederation(tenantID string) {
	for k := range s.fedIdentities {
		if k.TenantID == tenantID {
			delete(s.fedIdentities, k)
		}
	}
	for k := range s.fedTokens {
		if k.TenantID == tenantID {
			delete(s.fedTokens, k)
		}
	}
	purge(s.fedAttempts, tenantID)
}

// MicrosoftFederationSupported reports support for canonical Microsoft identities.
func (s *Store) MicrosoftFederationSupported(context.Context) error { return nil }
