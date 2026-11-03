package memory

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfarules"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type mfa struct{ s *Store }

func (s *Store) MFA() store.MFA { return mfa{s} }
func cloneGuardian(v *store.GuardianSettings) *store.GuardianSettings {
	n := *v
	n.Factors = maps.Clone(v.Factors)
	n.Policies = slices.Clone(v.Policies)
	n.Stored = maps.Clone(v.Stored)
	for k, b := range n.Stored {
		n.Stored[k] = bytes.Clone(b)
	}
	n.SealedSecrets = maps.Clone(v.SealedSecrets)
	for k, b := range n.SealedSecrets {
		n.SealedSecrets[k] = bytes.Clone(b)
	}
	return &n
}
func cloneAuthenticator(v *store.Authenticator) *store.Authenticator {
	n := *v
	n.SealedSecret = bytes.Clone(v.SealedSecret)
	n.CredentialID = bytes.Clone(v.CredentialID)
	n.PublicData = bytes.Clone(v.PublicData)
	n.PublicKey = bytes.Clone(v.PublicKey)
	return &n
}
func cloneMFAToken(v *store.MFAToken) *store.MFAToken {
	n := *v
	n.Request = bytes.Clone(v.Request)
	return &n
}
func cloneChallenge(v *store.MFAChallenge) *store.MFAChallenge {
	n := *v
	n.Challenge = bytes.Clone(v.Challenge)
	return &n
}
func (r mfa) GetGuardian(_ context.Context, tid string) (*store.GuardianSettings, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	if r.s.tenants[tid] == nil {
		return nil, store.ErrNotFound
	}
	if v := r.s.guardian[tid]; v != nil {
		return cloneGuardian(v), nil
	}
	v := &store.GuardianSettings{TenantID: tid, Factors: map[string]bool{}, Policies: []string{}}
	for _, f := range mfarules.Factors() {
		v.Factors[f.Name] = false
	}
	return v, nil
}
func (r mfa) PutGuardian(_ context.Context, v *store.GuardianSettings, version int) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.tenants[v.TenantID] == nil {
		return store.ErrNotFound
	}
	old := r.s.guardian[v.TenantID]
	if old == nil && version != 0 || old != nil && old.Version != version {
		return store.ErrConflict
	}
	n := cloneGuardian(v)
	n.Version = version + 1
	r.s.guardian[v.TenantID] = n
	return nil
}
func (r mfa) CreateAuthenticator(_ context.Context, a *store.Authenticator) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{a.TenantID, a.UserID}] == nil {
		return store.ErrNotFound
	}
	k := key{a.TenantID, a.ID}
	if r.s.authenticators[k] != nil {
		return store.ErrConflict
	}
	for _, x := range r.s.authenticators {
		if x.TenantID == a.TenantID && x.UserID == a.UserID && x.Type == "recovery-code" && a.Type == "recovery-code" {
			return store.ErrConflict
		}
		if x.TenantID == a.TenantID && len(a.CredentialID) > 0 && bytes.Equal(a.CredentialID, x.CredentialID) {
			return store.ErrConflict
		}
	}
	r.s.authenticators[k] = cloneAuthenticator(a)
	return nil
}
func (r mfa) GetAuthenticator(_ context.Context, tid, uid, id string) (*store.Authenticator, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	a := r.s.authenticators[key{tid, id}]
	if a == nil || a.UserID != uid {
		return nil, store.ErrNotFound
	}
	return cloneAuthenticator(a), nil
}
func (r mfa) ListAuthenticators(_ context.Context, tid, uid string) ([]store.Authenticator, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	out := []store.Authenticator{}
	for _, a := range r.s.authenticators {
		if a.TenantID == tid && a.UserID == uid {
			out = append(out, *cloneAuthenticator(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (r mfa) UpdateAuthenticator(_ context.Context, a *store.Authenticator) error {
	r.s.lock()
	defer r.s.unlock()
	v := r.s.authenticators[key{a.TenantID, a.ID}]
	if v == nil || v.UserID != a.UserID {
		return store.ErrNotFound
	}
	v.Name, v.Preferred, v.Confirmed, v.PhoneMethod = a.Name, a.Preferred, a.Confirmed, a.PhoneMethod
	return nil
}
func (r mfa) DeleteAuthenticator(_ context.Context, tid, uid, id string) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	a := r.s.authenticators[k]
	if a == nil || a.UserID != uid {
		return store.ErrNotFound
	}
	delete(r.s.authenticators, k)
	return nil
}
func (r mfa) DeleteUserAuthenticators(_ context.Context, tid, uid string, types []string) error {
	r.s.lock()
	defer r.s.unlock()
	for k, a := range r.s.authenticators {
		if k.tenant == tid && a.UserID == uid && (types == nil || slices.Contains(types, a.Type)) {
			delete(r.s.authenticators, k)
		}
	}
	return nil
}
func (r mfa) AcceptTOTPStep(_ context.Context, tid, uid, id string, step int64, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	a := r.s.authenticators[key{tid, id}]
	if a == nil || a.UserID != uid {
		return store.ErrNotFound
	}
	if step <= a.LastStep {
		return store.ErrPrecondition
	}
	a.LastStep = step
	a.LastAuthAt = at
	return nil
}
func (r mfa) ReplaceRecoveryCode(_ context.Context, tid, uid, oldHash, newHash string, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	if newHash == "" {
		return store.ErrInvalid
	}
	if r.s.users[key{tid, uid}] == nil {
		return store.ErrNotFound
	}
	for _, a := range r.s.authenticators {
		if a.TenantID == tid && a.UserID == uid && a.Type == "recovery-code" {
			if oldHash == "" || a.CodeHash != oldHash {
				return store.ErrPrecondition
			}
			a.CodeHash = newHash
			a.LastAuthAt = at
			return nil
		}
	}
	if oldHash != "" {
		return store.ErrPrecondition
	}
	for {
		id := "recovery-code|dev_" + secrets.RandomString(20)
		k := key{tid, id}
		if r.s.authenticators[k] != nil {
			continue
		}
		r.s.authenticators[k] = &store.Authenticator{TenantID: tid, UserID: uid, ID: id, Type: "recovery-code", Confirmed: true, CodeHash: newHash, CreatedAt: at}
		return nil
	}
}

func (r mfa) AcceptSignCount(_ context.Context, tid, uid, id string, count uint32, at time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	a := r.s.authenticators[key{tid, id}]
	if a == nil || a.UserID != uid {
		return store.ErrNotFound
	}
	if count <= a.SignCount && !(count == 0 && a.SignCount == 0) {
		return store.ErrPrecondition
	}
	a.SignCount = count
	a.LastAuthAt = at
	return nil
}
func (r mfa) CreateMFAToken(_ context.Context, v *store.MFAToken) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{v.TenantID, v.UserID}] == nil {
		return store.ErrNotFound
	}
	if v.ClientID != "" && r.s.clients[key{v.TenantID, v.ClientID}] == nil {
		return store.ErrNotFound
	}
	k := key{v.TenantID, v.Hash}
	if r.s.mfaTokens[k] != nil {
		return store.ErrConflict
	}
	r.s.mfaTokens[k] = cloneMFAToken(v)
	return nil
}
func (r mfa) ConsumeMFAToken(_ context.Context, tid, hash, client string, now time.Time) (*store.MFAToken, error) {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, hash}
	v := r.s.mfaTokens[k]
	if v == nil || v.ClientID != client || !now.Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	delete(r.s.mfaTokens, k)
	return cloneMFAToken(v), nil
}
func (r mfa) PeekMFAToken(_ context.Context, tid, hash string, now time.Time) (*store.MFAToken, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.mfaTokens[key{tid, hash}]
	if v == nil || !now.Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return cloneMFAToken(v), nil
}
func (r mfa) CreateChallenge(_ context.Context, v *store.MFAChallenge) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{v.TenantID, v.UserID}] == nil {
		return store.ErrNotFound
	}
	if v.AuthenticatorID != "" {
		a := r.s.authenticators[key{v.TenantID, v.AuthenticatorID}]
		if a == nil || a.UserID != v.UserID {
			return store.ErrNotFound
		}
	}
	k := key{v.TenantID, v.ID}
	if r.s.challenges[k] != nil {
		return store.ErrConflict
	}
	r.s.challenges[k] = cloneChallenge(v)
	return nil
}
func (r mfa) GetChallenge(_ context.Context, tid, id string, now time.Time) (*store.MFAChallenge, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.challenges[key{tid, id}]
	if v == nil || !now.Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return cloneChallenge(v), nil
}
func (r mfa) FailChallenge(_ context.Context, tid, id string) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	v := r.s.challenges[key{tid, id}]
	if v == nil {
		return 0, store.ErrNotFound
	}
	if v.Attempts >= 5 {
		return 0, store.ErrPrecondition
	}
	v.Attempts++
	return v.Attempts, nil
}
func (r mfa) ConsumeChallenge(_ context.Context, tid, id string, now time.Time) error {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, id}
	v := r.s.challenges[k]
	if v == nil || !now.Before(v.ExpiresAt) || ((v.Kind == "email" || v.Kind == "oob") && v.Attempts >= 5) {
		return store.ErrPrecondition
	}
	delete(r.s.challenges, k)
	return nil
}
func (r mfa) CreateTicket(_ context.Context, v *store.EnrollmentTicket) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{v.TenantID, v.UserID}] == nil {
		return store.ErrNotFound
	}
	k := key{v.TenantID, v.Hash}
	if r.s.tickets[k] != nil {
		return store.ErrConflict
	}
	r.s.tickets[k] = cloneValue(v)
	return nil
}
func (r mfa) ConsumeTicket(_ context.Context, tid, hash string, now time.Time) (*store.EnrollmentTicket, error) {
	r.s.lock()
	defer r.s.unlock()
	k := key{tid, hash}
	v := r.s.tickets[k]
	if v == nil || !now.Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	delete(r.s.tickets, k)
	return cloneValue(v), nil
}
func (r mfa) PeekTicket(_ context.Context, tid, hash string, now time.Time) (*store.EnrollmentTicket, error) {
	r.s.lock()
	defer r.s.unlock()
	v := r.s.tickets[key{tid, hash}]
	if v == nil || !now.Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return cloneValue(v), nil
}
func (r mfa) PutBrowser(_ context.Context, v *store.MFABrowser) error {
	r.s.lock()
	defer r.s.unlock()
	if r.s.users[key{v.TenantID, v.UserID}] == nil {
		return store.ErrNotFound
	}
	r.s.browsers[key{v.TenantID, v.Hash}] = cloneValue(v)
	return nil
}
func (r mfa) GetBrowser(_ context.Context, tid, hash string, now time.Time) (*store.MFABrowser, error) {
	r.s.readLock()
	defer r.s.readUnlock()
	v := r.s.browsers[key{tid, hash}]
	if v == nil || !now.Before(v.ExpiresAt) {
		return nil, store.ErrNotFound
	}
	return cloneValue(v), nil
}
func (r mfa) BumpRememberEpoch(_ context.Context, tid, uid string) error {
	r.s.lock()
	defer r.s.unlock()
	u := r.s.users[key{tid, uid}]
	if u == nil {
		return store.ErrNotFound
	}
	u.RememberBrowserEpoch++
	return nil
}
func (r mfa) PurgeMFA(_ context.Context, before time.Time, limit int) (int, error) {
	r.s.lock()
	defer r.s.unlock()
	n := 0
	take := func(t time.Time) bool {
		if (limit > 0 && n >= limit) || !t.Before(before) {
			return false
		}
		n++
		return true
	}
	for k, v := range r.s.mfaTokens {
		if take(v.ExpiresAt) {
			delete(r.s.mfaTokens, k)
		}
	}
	for k, v := range r.s.challenges {
		if take(v.ExpiresAt) {
			delete(r.s.challenges, k)
		}
	}
	for k, v := range r.s.tickets {
		if take(v.ExpiresAt) {
			delete(r.s.tickets, k)
		}
	}
	for k, v := range r.s.browsers {
		if take(v.ExpiresAt) {
			delete(r.s.browsers, k)
		}
	}
	return n, nil
}
func (r mfa) DeleteUserMFA(_ context.Context, tid, uid string) error {
	r.s.lock()
	defer r.s.unlock()
	r.s.deleteUserMFA(tid, uid)
	return nil
}
func (s *Store) deleteUserMFA(tid, uid string) {
	for k, v := range s.authenticators {
		if k.tenant == tid && v.UserID == uid {
			delete(s.authenticators, k)
		}
	}
	for k, v := range s.mfaTokens {
		if k.tenant == tid && v.UserID == uid {
			delete(s.mfaTokens, k)
		}
	}
	for k, v := range s.challenges {
		if k.tenant == tid && v.UserID == uid {
			delete(s.challenges, k)
		}
	}
	for k, v := range s.tickets {
		if k.tenant == tid && v.UserID == uid {
			delete(s.tickets, k)
		}
	}
	for k, v := range s.browsers {
		if k.tenant == tid && v.UserID == uid {
			delete(s.browsers, k)
		}
	}
}
func (r mfa) DeleteTenantMFA(_ context.Context, tid string) error {
	r.s.lock()
	defer r.s.unlock()
	r.s.deleteTenantMFA(tid)
	return nil
}
func (s *Store) deleteTenantMFA(tid string) {
	delete(s.guardian, tid)
	purge(s.authenticators, tid)
	purge(s.mfaTokens, tid)
	purge(s.challenges, tid)
	purge(s.tickets, tid)
	purge(s.browsers, tid)
}
