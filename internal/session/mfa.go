package session

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const MFARememberCookie = "za_mfa_rb"
const MFADeviceCookie = "za_mfa_dev"
const MFABrowserLifetime = 30 * 24 * time.Hour

// MarkMFA is called only after the MFA service accepts a proof. Mutating a
// caller's session is insufficient: the durable, current session is authoritative.
func (m *Manager) MarkMFA(ctx context.Context, s *store.LoginSession) error {
	if s == nil {
		return store.ErrNotFound
	}
	at := m.now()
	if err := m.Store.Sessions().MarkMFA(ctx, s.TenantID, s.ID, at); err != nil {
		return err
	}
	s.MFAAt = at
	return nil
}
func browserCookie(kind string) string {
	switch kind {
	case "remember":
		return MFARememberCookie
	case "device":
		return MFADeviceCookie
	}
	return ""
}

// MFABrowserValid binds both browser cookies to tenant, user, kind, current
// invalidation epoch and expiry. The raw cookie is never stored.
func (m *Manager) MFABrowserValid(ctx context.Context, r *http.Request, u *store.User, kind string) (bool, error) {
	name := browserCookie(kind)
	if name == "" || u == nil {
		return false, store.ErrInvalid
	}
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return false, nil
	}
	b, err := m.Store.MFA().GetBrowser(ctx, u.TenantID, secrets.HashToken(c.Value), m.now())
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return b.TenantID == u.TenantID && b.UserID == u.UserID && b.Kind == kind && b.Epoch == u.RememberBrowserEpoch && m.now().Before(b.ExpiresAt), nil
}

// SetMFABrowser creates a 30-day host-only cookie after a successful login or
// MFA proof. Callers set remember only when the sealed requirement allows it.
func (m *Manager) SetMFABrowser(ctx context.Context, w http.ResponseWriter, u *store.User, kind string) error {
	name := browserCookie(kind)
	if name == "" || u == nil {
		return store.ErrInvalid
	}
	token := secrets.RandomString(43)
	expires := m.now().Add(MFABrowserLifetime)
	if err := m.Store.MFA().PutBrowser(ctx, &store.MFABrowser{TenantID: u.TenantID, UserID: u.UserID, Kind: kind, Hash: secrets.HashToken(token), Epoch: u.RememberBrowserEpoch, ExpiresAt: expires}); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: token, Path: "/", Expires: expires, MaxAge: int(MFABrowserLifetime / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	return nil
}
