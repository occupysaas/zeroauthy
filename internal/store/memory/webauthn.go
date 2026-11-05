package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type webauthnRepo struct{ s *Store }

func (s *Store) WebAuthn() store.WebAuthn { return webauthnRepo{s} }

func snoozeKey(tid, uid, kind, scope string) key {
	return key{tid, uid + "\x00" + kind + "\x00" + scope}
}

func cloneSnooze(v *store.WebAuthnSnooze) *store.WebAuthnSnooze { n := *v; return &n }

// credentialTaken reports whether the tenant already has the credential ID.
func (s *Store) credentialTaken(tid string, id []byte) bool {
	for _, x := range s.authenticators {
		if x.TenantID == tid && len(id) > 0 && bytes.Equal(x.CredentialID, id) {
			return true
		}
	}
	return false
}

func (r webauthnRepo) GetAuthenticatorByCredentialID(_ context.Context, tid string, credID []byte) (*store.Authenticator, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	for _, x := range r.s.authenticators {
		if x.TenantID == tid && len(credID) > 0 && bytes.Equal(x.CredentialID, credID) {
			return cloneAuthenticator(x), nil
		}
	}
	return nil, store.ErrNotFound
}

// insertPasskey checks and inserts under the caller's write lock, so the
// limit check and the insert are one step.
func (s *Store) insertPasskey(a *store.Authenticator, limit int) error {
	if s.users[key{a.TenantID, a.UserID}] == nil {
		return store.ErrNotFound
	}
	if s.authenticators[key{a.TenantID, a.ID}] != nil || s.credentialTaken(a.TenantID, a.CredentialID) {
		return store.ErrConflict
	}
	n := 0
	for _, x := range s.authenticators {
		if x.TenantID == a.TenantID && x.UserID == a.UserID && x.Type == "passkey" {
			n++
		}
	}
	if limit > 0 && n >= limit {
		return store.ErrPrecondition
	}
	s.authenticators[key{a.TenantID, a.ID}] = cloneAuthenticator(a)
	return nil
}

func (r webauthnRepo) CreatePasskey(_ context.Context, a *store.Authenticator, limit int) error {
	r.s.lock()
	defer r.s.unlock()
	return r.s.insertPasskey(a, limit)
}

func (r webauthnRepo) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	return r.s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		return tx.WebAuthn().CreatePasskey(ctx, a, 0)
	})
}

func (r webauthnRepo) AcceptAssertion(_ context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	a := r.s.authenticators[key{tid, id}]
	if a == nil || a.UserID != uid {
		return store.ErrNotFound
	}
	if count <= a.SignCount && !(count == 0 && a.SignCount == 0) {
		return store.ErrPrecondition
	}
	pub := map[string]any{}
	if len(a.PublicData) > 0 {
		_ = json.Unmarshal(a.PublicData, &pub)
	}
	pub["backed_up"] = backedUp
	b, err := json.Marshal(pub)
	if err != nil {
		return err
	}
	a.PublicData, a.SignCount, a.LastAuthAt = b, count, at
	return nil
}

func (r webauthnRepo) MovePasskeys(_ context.Context, tid, fromUID, toUID, identityUserID string) error {
	r.s.lock()
	defer r.s.unlock()
	for _, a := range r.s.authenticators {
		if a.TenantID != tid || a.UserID != fromUID || a.Type != "passkey" {
			continue
		}
		if identityUserID != "" {
			var pub struct {
				IdentityUserID string `json:"identity_user_id"`
			}
			_ = json.Unmarshal(a.PublicData, &pub)
			if pub.IdentityUserID != identityUserID {
				continue
			}
		}
		a.UserID = toUID
	}
	return nil
}

func (r webauthnRepo) PutSnooze(_ context.Context, v *store.WebAuthnSnooze) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[v.TenantID] == nil {
		return store.ErrNotFound
	}
	r.s.webauthnSnoozes[snoozeKey(v.TenantID, v.UserID, v.Kind, v.ScopeKey)] = cloneSnooze(v)
	return nil
}

func (r webauthnRepo) GetSnooze(_ context.Context, tid, uid, kind, scope string, now time.Time) (*store.WebAuthnSnooze, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.webauthnSnoozes[snoozeKey(tid, uid, kind, scope)]
	if v == nil || !now.Before(v.Until) {
		return nil, store.ErrNotFound
	}
	return cloneSnooze(v), nil
}

func (r webauthnRepo) HostTenantsUnder(_ context.Context, suffix string, limit int) ([]string, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	seen := map[string]bool{}
	for host, b := range r.s.hostBindings {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			seen[b.TenantID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for tid := range seen {
		out = append(out, tid)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r webauthnRepo) PurgeWebAuthn(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	keys := make([]key, 0)
	for k, v := range r.s.webauthnSnoozes {
		if v.Until.Before(before) {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b key) int { return strings.Compare(a.tenant+a.id, b.tenant+b.id) })
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	for _, k := range keys {
		delete(r.s.webauthnSnoozes, k)
	}
	return len(keys), nil
}

func (s *Store) deleteUserWebAuthn(tid, uid string) {
	for k, v := range s.webauthnSnoozes {
		if k.tenant == tid && v.UserID == uid {
			delete(s.webauthnSnoozes, k)
		}
	}
}
