package memory

import (
	"bytes"
	"context"
	"crypto/subtle"
	"sort"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type phoneRepo struct{ s *Store }

func (s *Store) Phone() store.Phone { return phoneRepo{s} }

func cloneProvider(v *store.PhoneProvider) *store.PhoneProvider {
	n := *v
	n.Configuration = bytes.Clone(v.Configuration)
	n.SealedCredentials = bytes.Clone(v.SealedCredentials)
	return &n
}
func clonePhoneTemplate(v *store.PhoneTemplate) *store.PhoneTemplate {
	n := *v
	n.Content = bytes.Clone(v.Content)
	return &n
}
func clonePasswordlessCode(v *store.PasswordlessCode) *store.PasswordlessCode {
	n := *v
	n.Request = bytes.Clone(v.Request)
	return &n
}

// codeKey packs the row identity into a key so tenant purge works unchanged.
func codeKey(tid, conn, ident, kind string) key {
	return key{tid, conn + "\x00" + ident + "\x00" + kind}
}

func (r phoneRepo) ListPhoneProviders(_ context.Context, tid string) ([]store.PhoneProvider, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.PhoneProvider{}
	for k, v := range r.s.phoneProviders {
		if k.tenant == tid {
			out = append(out, *cloneProvider(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (r phoneRepo) GetPhoneProvider(_ context.Context, tid, id string) (*store.PhoneProvider, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.phoneProviders[key{tid, id}]
	if v == nil {
		return nil, store.ErrNotFound
	}
	return cloneProvider(v), nil
}
func (r phoneRepo) CreatePhoneProvider(_ context.Context, p *store.PhoneProvider) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[p.TenantID] == nil {
		return store.ErrNotFound
	}
	for k := range r.s.phoneProviders {
		if k.tenant == p.TenantID {
			return store.ErrConflict
		}
	}
	r.s.phoneProviders[key{p.TenantID, p.ID}] = cloneProvider(p)
	return nil
}
func (r phoneRepo) UpdatePhoneProvider(_ context.Context, p *store.PhoneProvider) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{p.TenantID, p.ID}
	old := r.s.phoneProviders[k]
	if old == nil {
		return store.ErrNotFound
	}
	n := cloneProvider(p)
	n.CreatedAt = old.CreatedAt
	r.s.phoneProviders[k] = n
	return nil
}
func (r phoneRepo) DeletePhoneProvider(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	if r.s.phoneProviders[k] == nil {
		return store.ErrNotFound
	}
	delete(r.s.phoneProviders, k)
	return nil
}

func (r phoneRepo) ListPhoneTemplates(_ context.Context, tid string) ([]store.PhoneTemplate, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.PhoneTemplate{}
	for k, v := range r.s.phoneTemplates {
		if k.tenant == tid {
			out = append(out, *clonePhoneTemplate(v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (r phoneRepo) GetPhoneTemplate(_ context.Context, tid, id string) (*store.PhoneTemplate, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.phoneTemplates[key{tid, id}]
	if v == nil {
		return nil, store.ErrNotFound
	}
	return clonePhoneTemplate(v), nil
}
func (r phoneRepo) PutPhoneTemplate(_ context.Context, t *store.PhoneTemplate) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[t.TenantID] == nil {
		return store.ErrNotFound
	}
	k := key{t.TenantID, t.ID}
	for ok, v := range r.s.phoneTemplates {
		if ok.tenant == t.TenantID && ok != k && v.Type == t.Type {
			return store.ErrConflict
		}
	}
	n := clonePhoneTemplate(t)
	if old := r.s.phoneTemplates[k]; old != nil {
		n.CreatedAt = old.CreatedAt
	}
	r.s.phoneTemplates[k] = n
	return nil
}
func (r phoneRepo) DeletePhoneTemplate(_ context.Context, tid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	if r.s.phoneTemplates[k] == nil {
		return store.ErrNotFound
	}
	delete(r.s.phoneTemplates, k)
	return nil
}

func (r phoneRepo) PutPasswordlessCode(_ context.Context, c *store.PasswordlessCode) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[c.TenantID] == nil {
		return store.ErrNotFound
	}
	r.s.passwordlessCodes[codeKey(c.TenantID, c.ConnectionID, c.Identifier, c.Kind)] = clonePasswordlessCode(c)
	return nil
}
func (r phoneRepo) FailPasswordlessCode(_ context.Context, tid, conn, ident, kind string, _ time.Time) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	v := r.s.passwordlessCodes[codeKey(tid, conn, ident, kind)]
	if v == nil {
		return 0, store.ErrNotFound
	}
	v.Attempts++
	return v.Attempts, nil
}
func (r phoneRepo) ConsumePasswordlessCode(_ context.Context, tid, conn, ident, kind, hash string, maxAttempts int, now time.Time) (*store.PasswordlessCode, error) {
	r.s.lock()
	defer r.s.unlock()
	k := codeKey(tid, conn, ident, kind)
	v := r.s.passwordlessCodes[k]
	if v == nil || v.Attempts >= maxAttempts || !now.Before(v.ExpiresAt) {
		return nil, store.ErrPrecondition
	}
	if subtle.ConstantTimeCompare([]byte(v.CodeHash), []byte(hash)) != 1 {
		// A wrong guess is counted under the same lock as the check.
		v.Attempts++
		return nil, store.ErrPrecondition
	}
	delete(r.s.passwordlessCodes, k)
	return clonePasswordlessCode(v), nil
}
func (r phoneRepo) PeekPasswordlessLink(_ context.Context, tid, hash string, now time.Time) (*store.PasswordlessCode, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for k, v := range r.s.passwordlessCodes {
		if k.tenant == tid && v.Kind == "link" && now.Before(v.ExpiresAt) &&
			subtle.ConstantTimeCompare([]byte(v.CodeHash), []byte(hash)) == 1 {
			return clonePasswordlessCode(v), nil
		}
	}
	return nil, store.ErrNotFound
}

func (r phoneRepo) FindUsersByPhone(_ context.Context, tid, connection, e164 string) ([]store.User, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.User{}
	if e164 == "" {
		return out, nil
	}
	for k, u := range r.s.users {
		if k.tenant != tid || u.PhoneNormalized != e164 {
			continue
		}
		for _, id := range u.Identities {
			if id.Connection == connection {
				out = append(out, *cloneUser(u))
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID < out[j].UserID })
	return out, nil
}
func (r phoneRepo) PurgePhone(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	for k, v := range r.s.passwordlessCodes {
		if limit > 0 && n >= limit {
			break
		}
		if v.ExpiresAt.Before(before) {
			delete(r.s.passwordlessCodes, k)
			n++
		}
	}
	return n, nil
}
func (r phoneRepo) DeleteTenantPhone(_ context.Context, tid string) error {
	r.s.lock()
	defer r.s.unlock()
	r.s.deleteTenantPhone(tid)
	return nil
}
func (s *Store) deleteTenantPhone(tid string) {
	purge(s.phoneProviders, tid)
	purge(s.phoneTemplates, tid)
	purge(s.passwordlessCodes, tid)
}
