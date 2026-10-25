package memory

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type signingKeys struct{ s *Store }

func (r signingKeys) Create(_ context.Context, k *store.SigningKey) error {
	r.s.lock()
	defer r.s.unlock()
	kk := key{k.TenantID, k.KID}
	if _, ok := r.s.signingKeys[kk]; ok || r.customHasKID(k.TenantID, k.KID) {
		return store.ErrConflict
	}
	if k.Status == store.KeyCurrent || k.Status == store.KeyNext {
		for ok, sk := range r.s.signingKeys {
			if ok.tenant == k.TenantID && sk.Status == k.Status {
				return store.ErrConflict
			}
		}
	}
	r.s.signingKeys[kk] = cloneSigningKey(k)
	return nil
}

func (r signingKeys) Get(_ context.Context, tenantID, kid string) (*store.SigningKey, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	k, ok := r.s.signingKeys[key{tenantID, kid}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSigningKey(k), nil
}

func (r signingKeys) List(_ context.Context, tenantID string) ([]*store.SigningKey, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []*store.SigningKey
	for k, sk := range r.s.signingKeys {
		if k.tenant == tenantID {
			out = append(out, cloneSigningKey(sk))
		}
	}
	slices.SortFunc(out, func(a, b *store.SigningKey) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.KID, b.KID)
	})
	return out, nil
}

func (r signingKeys) Rotate(ctx context.Context, tenantID string, next *store.SigningKey) error {
	if next == nil {
		return store.ErrInvalid
	}
	_, err := r.RotateWithResult(ctx, tenantID, next, next.CreatedAt)
	return err
}

func (r signingKeys) RotateWithResult(_ context.Context, tenantID string, next *store.SigningKey, at time.Time) (*store.SigningKeyRotation, error) {
	if next == nil {
		return nil, store.ErrInvalid
	}
	if next.Status != store.KeyNext || next.TenantID != tenantID || next.KID == "" {
		return nil, errors.Join(store.ErrInvalid, errors.New("store: rotation key must be a named next key for the tenant"))
	}
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.signingKeys[key{tenantID, next.KID}]; ok || r.customHasKID(tenantID, next.KID) {
		return nil, store.ErrConflict
	}
	var current, queued *store.SigningKey
	for k, sk := range r.s.signingKeys {
		if k.tenant != tenantID {
			continue
		}
		if sk.Status == store.KeyCurrent {
			current = sk
		}
		if sk.Status == store.KeyNext {
			queued = sk
		}
	}
	if queued == nil {
		return nil, store.ErrNotFound
	}
	if current == nil {
		return nil, store.ErrInvalid
	}
	at = at.UTC()
	current.Status = store.KeyPrevious
	current.CurrentUntil = timeCopy(&at)
	queued.Status = store.KeyCurrent
	queued.CurrentSince = timeCopy(&at)
	queued.CurrentUntil = nil
	queued.RevokedAt = nil
	newNext := cloneSigningKey(next)
	newNext.CurrentSince, newNext.CurrentUntil, newNext.RevokedAt = nil, nil, nil
	r.s.signingKeys[key{tenantID, newNext.KID}] = newNext
	return &store.SigningKeyRotation{Current: cloneSigningKey(queued), Next: cloneSigningKey(newNext)}, nil
}

func (r signingKeys) Revoke(_ context.Context, tenantID, kid string, at time.Time) (*store.SigningKey, error) {
	r.s.lock()
	defer r.s.unlock()
	k, ok := r.s.signingKeys[key{tenantID, kid}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if k.Status == store.KeyRevoked {
		return cloneSigningKey(k), nil
	}
	if k.Status != store.KeyPrevious {
		return nil, store.ErrInvalid
	}
	k.Status = store.KeyRevoked
	at = at.UTC()
	k.RevokedAt = timeCopy(&at)
	return cloneSigningKey(k), nil
}

func (r signingKeys) SetCertificateIfAbsent(_ context.Context, tenantID, kid string, der []byte) (*store.SigningKey, error) {
	r.s.lock()
	defer r.s.unlock()
	k, ok := r.s.signingKeys[key{tenantID, kid}]
	if !ok {
		return nil, store.ErrNotFound
	}
	if len(k.CertificateDER) == 0 {
		k.CertificateDER = slices.Clone(der)
	}
	return cloneSigningKey(k), nil
}

func timeCopy(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

type customSigningKeys struct{ s *Store }

func (s *Store) CustomSigningKeys() store.CustomSigningKeys { return customSigningKeys{s} }

func (r customSigningKeys) Get(_ context.Context, tenantID string) (*store.CustomSigningKeySet, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	set, ok := r.s.customSigningKeys[tenantID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneCustomSigningKeySet(set), nil
}

func (r customSigningKeys) Replace(_ context.Context, set *store.CustomSigningKeySet) error {
	if set == nil || set.TenantID == "" || len(set.JWKS) == 0 {
		return store.ErrInvalid
	}
	ids, err := customKeyIDs(set.JWKS)
	if err != nil {
		return errors.Join(store.ErrInvalid, err)
	}
	r.s.lock()
	defer r.s.unlock()
	for _, kid := range ids {
		if _, ok := r.s.signingKeys[key{set.TenantID, kid}]; ok {
			return store.ErrConflict
		}
	}
	r.s.customSigningKeys[set.TenantID] = cloneCustomSigningKeySet(set)
	return nil
}

func (r customSigningKeys) Delete(_ context.Context, tenantID string) error {
	r.s.lock()
	defer r.s.unlock()
	delete(r.s.customSigningKeys, tenantID)
	return nil
}

func (r signingKeys) customHasKID(tenantID, kid string) bool {
	set := r.s.customSigningKeys[tenantID]
	if set == nil {
		return false
	}
	ids, err := customKeyIDs(set.JWKS)
	if err != nil {
		return true
	}
	return slices.Contains(ids, kid)
}

func customKeyIDs(raw []byte) ([]string, error) {
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	ids := make([]string, len(set.Keys))
	for i := range set.Keys {
		ids[i] = set.Keys[i].KID
	}
	return ids, nil
}
