// Package session manages login session cookies. The cookie carries a
// random token; the store holds only its SHA-256.
package session

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

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
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func lifetimes(t *store.Tenant) (absolute, idle time.Duration) {
	absolute, idle = DefaultLifetime, DefaultIdleLifetime
	if t.SessionLifetime > 0 {
		absolute = time.Duration(t.SessionLifetime) * time.Second
	}
	if t.IdleSessionLifetime > 0 {
		idle = time.Duration(t.IdleSessionLifetime) * time.Second
	}
	return absolute, idle
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
	_, idle := lifetimes(t)
	idleAt := minTime(now.Add(idle), s.ExpiresAt)
	if err := m.Store.Sessions().Touch(ctx, t.ID, s.ID, idleAt); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil // deleted (e.g. logout) since it was read
		}
		return nil, err
	}
	s.IdleExpiresAt = idleAt
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
	absolute, idle := lifetimes(t)
	token := secrets.RandomString(43)
	s := &store.LoginSession{
		TenantID:        t.ID,
		ID:              secrets.RandomString(24),
		TokenHash:       secrets.HashToken(token),
		UserID:          userID,
		Connection:      connection,
		AuthenticatedAt: authTime.UTC(),
		ExpiresAt:       now.Add(absolute),
		IdleExpiresAt:   minTime(now.Add(idle), now.Add(absolute)),
		CreatedAt:       now,
	}
	if err := m.Store.Sessions().Create(ctx, s); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   true,
		// None so the cookie reaches the hidden iframe used for silent
		// authentication (response_mode=web_message).
		SameSite: http.SameSiteNoneMode,
	})
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
