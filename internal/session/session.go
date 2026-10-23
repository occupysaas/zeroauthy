// Package session manages login session cookies. The cookie carries a
// random token; the store holds only its SHA-256.
package session

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const CookieName = "za_session"

const (
	DefaultLifetime     = 7 * 24 * time.Hour
	DefaultIdleLifetime = 3 * 24 * time.Hour
)

type Manager struct {
	Store store.Store
	Now   func() time.Time
	// TrustProxyHeaders reads the client address from X-Forwarded-For, as
	// everywhere else (httpx.ClientIP).
	TrustProxyHeaders bool
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

// lifetimes returns seconds, avoiding time.Duration overflow for API-valid
// policies longer than 292 years. Empty session mode is legacy persistent.
func lifetimes(t *store.Tenant, mode string) (absolute, idle int) {
	absolute, idle = t.SessionLifetime, t.IdleSessionLifetime
	da, di := int(DefaultLifetime/time.Second), int(DefaultIdleLifetime/time.Second)
	if mode == "non-persistent" {
		absolute, idle = t.EphemeralSessionLifetime, t.IdleEphemeralSessionLifetime
		da, di = 72*3600, 24*3600
	}
	if absolute <= 0 {
		absolute = da
	}
	if idle <= 0 {
		idle = di
	}
	return absolute, idle
}

// expiry saturates at the latest cookie/JSON-representable second. Check the
// remaining range before adding seconds, so even MaxInt64 cannot wrap.
func expiry(now time.Time, seconds int) time.Time {
	limit := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	if !now.Before(limit) || int64(seconds) >= limit.Unix()-now.Unix() {
		return limit
	}
	return time.Unix(now.Unix()+int64(seconds), int64(now.Nanosecond())).UTC()
}

// Current returns the request's valid session for tenant t, or nil. Each
// call extends the idle expiry, never past the absolute expiry.
func (m *Manager) Current(ctx context.Context, r *http.Request, t *store.Tenant) (*store.LoginSession, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		if err := m.Store.Sessions().Delete(ctx, t.ID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, nil
	}
	_, idle := lifetimes(t, s.CookieMode)
	idleAt := minTime(expiry(now, idle), s.ExpiresAt)
	ip, ua := httpx.RecordedIP(r, m.TrustProxyHeaders), r.UserAgent()
	if err := m.Store.Sessions().Touch(ctx, t.ID, s.ID, now, idleAt, ip, ua); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil // deleted (e.g. logout) since it was read
		}
		return nil, err
	}
	s.IdleExpiresAt = idleAt
	s.UpdatedAt, s.LastInteractedAt = now, now
	s.LastIP, s.LastUserAgent = ip, ua
	return s, nil
}

// Start creates a session for a freshly authenticated user and sets the
// cookie. Any session the request already carries is deleted first, so a
// login always gets a new session identifier.
func (m *Manager) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant, userID, connection string, authTime time.Time) (*store.LoginSession, error) {
	if old, err := r.Cookie(CookieName); err == nil && old.Value != "" {
		if s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(old.Value)); err == nil {
			_ = m.Store.Sessions().Delete(ctx, t.ID, s.ID)
		}
	}
	now := m.now()
	ip, ua := httpx.RecordedIP(r, m.TrustProxyHeaders), r.UserAgent()
	mode := t.SessionCookieMode
	if mode == "" {
		mode = "persistent"
	}
	absolute, idle := lifetimes(t, mode)
	token := secrets.RandomString(43)
	s := &store.LoginSession{
		CookieMode:      mode,
		TenantID:        t.ID,
		ID:              secrets.RandomString(24),
		TokenHash:       secrets.HashToken(token),
		UserID:          userID,
		Connection:      connection,
		AuthenticatedAt: authTime.UTC(),
		ExpiresAt:       expiry(now, absolute),
		IdleExpiresAt:   minTime(expiry(now, idle), expiry(now, absolute)),
		CreatedAt:       now,
		UpdatedAt:       now, LastInteractedAt: now,
		InitialIP: ip, InitialUserAgent: ua, LastIP: ip, LastUserAgent: ua,
	}
	if err := m.Store.Sessions().Create(ctx, s); err != nil {
		return nil, err
	}
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		// None so the cookie reaches the hidden iframe used for silent
		// authentication (response_mode=web_message).
		SameSite: http.SameSiteNoneMode,
	}
	if mode == "non-persistent" {
		cookie.Expires = time.Time{}
	}
	http.SetCookie(w, cookie)
	return s, nil
}

// AddClient records that clientID received tokens through s.
func (m *Manager) AddClient(ctx context.Context, s *store.LoginSession, clientID string) error {
	if slices.Contains(s.ClientIDs, clientID) {
		return nil
	}
	if err := m.Store.Sessions().AddClient(ctx, s.TenantID, s.ID, clientID); err != nil {
		return err
	}
	s.ClientIDs = append(s.ClientIDs, clientID)
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// End deletes the request's session, if any, and clears the cookie. It
// returns the ended session, or nil if there was none.
func (m *Manager) End(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant) (*store.LoginSession, error) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
	})
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := m.Store.Sessions().Delete(ctx, t.ID, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	return s, nil
}

// Lookup returns the request's unexpired session for t, or nil, without
// extending it. Logout uses it to decide whether to ask for confirmation.
func (m *Manager) Lookup(ctx context.Context, r *http.Request, t *store.Tenant) (*store.LoginSession, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		return nil, nil
	}
	return s, nil
}
