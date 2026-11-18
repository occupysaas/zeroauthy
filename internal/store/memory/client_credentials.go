package memory

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type clientCredentials struct{ s *Store }

func cloneClientCredential(c *store.ClientCredential) *store.ClientCredential {
	out := *c
	out.PublicKeyDER = bytes.Clone(c.PublicKeyDER)
	out.ExpiresAt = cloneTime(c.ExpiresAt)
	return &out
}

func jtiKey(tid, clientID, jti string) key {
	sum := sha256.Sum256([]byte(jti))
	return key{tid, clientID + "\x00" + hex.EncodeToString(sum[:])}
}

// dropClientCredentials removes a deleted client's credentials and jtis. The
// caller holds the write lock.
func (s *Store) dropClientCredentials(tid, clientID string) {
	for k, c := range s.credentials {
		if k.tenant == tid && c.ClientID == clientID {
			delete(s.credentials, k)
		}
	}
	for k := range s.assertionJTIs {
		if k.tenant == tid && strings.HasPrefix(k.id, clientID+"\x00") {
			delete(s.assertionJTIs, k)
		}
	}
}

// credential returns the credential owned by clientID; the caller holds a lock.
func (s *Store) credential(tid, clientID, id string) (*store.ClientCredential, error) {
	c, ok := s.credentials[key{tid, id}]
	if !ok || c.ClientID != clientID {
		return nil, store.ErrNotFound
	}
	return c, nil
}

func (r clientCredentials) Create(_ context.Context, c *store.ClientCredential, limit int) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.clients[key{c.TenantID, c.ClientID}]; !ok {
		return store.ErrNotFound
	}
	if _, ok := r.s.credentials[key{c.TenantID, c.ID}]; ok {
		return store.ErrConflict
	}
	n := 0
	for k, x := range r.s.credentials {
		if k.tenant == c.TenantID && x.ClientID == c.ClientID {
			n++
		}
	}
	if n >= limit {
		return store.ErrPrecondition
	}
	r.s.credentials[key{c.TenantID, c.ID}] = cloneClientCredential(c)
	return nil
}

func (r clientCredentials) Get(_ context.Context, tid, clientID, id string) (*store.ClientCredential, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	c, err := r.s.credential(tid, clientID, id)
	if err != nil {
		return nil, err
	}
	return cloneClientCredential(c), nil
}

func (r clientCredentials) List(_ context.Context, tid, clientID string) ([]*store.ClientCredential, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var out []*store.ClientCredential
	for k, c := range r.s.credentials {
		if k.tenant == tid && c.ClientID == clientID {
			out = append(out, cloneClientCredential(c))
		}
	}
	slices.SortFunc(out, func(a, b *store.ClientCredential) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	return out, nil
}

func (r clientCredentials) UpdateExpiry(_ context.Context, tid, clientID, id string, exp *time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	c, err := r.s.credential(tid, clientID, id)
	if err != nil {
		return err
	}
	c.ExpiresAt = cloneTime(exp)
	c.UpdatedAt = r.s.now()
	return nil
}

func (r clientCredentials) Delete(_ context.Context, tid, clientID, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if _, err := r.s.credential(tid, clientID, id); err != nil {
		return err
	}
	delete(r.s.credentials, key{tid, id})
	if c := r.s.clients[key{tid, clientID}]; c != nil {
		c.PrivateKeyJWTCredentials = slices.DeleteFunc(c.PrivateKeyJWTCredentials, func(x string) bool { return x == id })
		if c.SignedRequestObject != nil {
			c.SignedRequestObject.Credentials = slices.DeleteFunc(c.SignedRequestObject.Credentials, func(x string) bool { return x == id })
		}
	}
	return nil
}

func (r clientCredentials) UseJTI(_ context.Context, tid, clientID, jti string, exp time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	k := jtiKey(tid, clientID, jti)
	if old, ok := r.s.assertionJTIs[k]; ok && old.After(r.s.now()) {
		return store.ErrConflict
	}
	r.s.assertionJTIs[k] = exp
	return nil
}

func (r clientCredentials) PurgeJTIs(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, exp := range r.s.assertionJTIs {
		if n >= limit {
			break
		}
		if !exp.After(before) {
			delete(r.s.assertionJTIs, k)
			n++
		}
	}
	return n, nil
}

// typeTaken reports whether another profile of the tenant has the subject
// token type; the caller holds a lock.
func (s *Store) typeTaken(tid, id, subjectTokenType string) bool {
	for k, p := range s.exchangeProfiles {
		if k.tenant == tid && p.ID != id && p.SubjectTokenType == subjectTokenType {
			return true
		}
	}
	return false
}

func (r clientCredentials) CreateProfile(_ context.Context, p *store.TokenExchangeProfile, limit int) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.exchangeProfiles[key{p.TenantID, p.ID}]; ok || r.s.typeTaken(p.TenantID, p.ID, p.SubjectTokenType) {
		return store.ErrConflict
	}
	n := 0
	for k := range r.s.exchangeProfiles {
		if k.tenant == p.TenantID {
			n++
		}
	}
	if n >= limit {
		return store.ErrPrecondition
	}
	r.s.exchangeProfiles[key{p.TenantID, p.ID}] = cloneValue(p)
	return nil
}

func (r clientCredentials) GetProfile(_ context.Context, tid, id string) (*store.TokenExchangeProfile, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	p, ok := r.s.exchangeProfiles[key{tid, id}]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneValue(p), nil
}

func (r clientCredentials) GetProfileByType(_ context.Context, tid, subjectTokenType string) (*store.TokenExchangeProfile, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, p := range r.s.exchangeProfiles {
		if k.tenant == tid && p.SubjectTokenType == subjectTokenType {
			return cloneValue(p), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r clientCredentials) ListProfiles(_ context.Context, tid, from string, take int) ([]*store.TokenExchangeProfile, string, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	var all []*store.TokenExchangeProfile
	for k, p := range r.s.exchangeProfiles {
		if k.tenant == tid && p.ID > from {
			all = append(all, p)
		}
	}
	slices.SortFunc(all, func(a, b *store.TokenExchangeProfile) int { return strings.Compare(a.ID, b.ID) })
	next := ""
	if take >= 0 && len(all) > take {
		all = all[:take]
		if take > 0 {
			next = all[take-1].ID
		}
	}
	out := make([]*store.TokenExchangeProfile, len(all))
	for i, p := range all {
		out[i] = cloneValue(p)
	}
	return out, next, nil
}

func (r clientCredentials) UpdateProfile(_ context.Context, p *store.TokenExchangeProfile) error {
	r.s.lock()
	defer r.s.unlock()
	old, ok := r.s.exchangeProfiles[key{p.TenantID, p.ID}]
	if !ok {
		return store.ErrNotFound
	}
	if r.s.typeTaken(p.TenantID, p.ID, p.SubjectTokenType) {
		return store.ErrConflict
	}
	old.Name, old.SubjectTokenType, old.ActionID, old.UpdatedAt = p.Name, p.SubjectTokenType, p.ActionID, p.UpdatedAt
	return nil
}

func (r clientCredentials) DeleteProfile(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	if _, ok := r.s.exchangeProfiles[key{tid, id}]; !ok {
		return store.ErrNotFound
	}
	delete(r.s.exchangeProfiles, key{tid, id})
	return nil
}

func (r clientCredentials) ProfilesForAction(_ context.Context, tid, actionID string) (int, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	n := 0
	for k, p := range r.s.exchangeProfiles {
		if k.tenant == tid && p.ActionID == actionID {
			n++
		}
	}
	return n, nil
}
