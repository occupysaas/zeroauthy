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
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const CookieName = "za_session"

const (
	DefaultLifetime     = 7 * 24 * time.Hour
	DefaultIdleLifetime = 3 * 24 * time.Hour
)

type Manager struct {
	// OnEnd enqueues notifications inside the same transaction as local deletion.
	OnEnd func(context.Context, store.Store, *store.LoginSession) error
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
	if errors.Is(err, store.ErrNotFound) || err == nil && !sameOrigin(r, s) {
		// Another public origin's session is not this request's session; it
		// is neither extended nor ended here.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := m.now()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		// The expiry sweeper owns the transactional notification snapshot.
		if m.OnEnd != nil {
			return nil, nil
		}
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
func (m *Manager) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant, userID, connection string, authTime time.Time, methods ...store.AuthMethod) (*store.LoginSession, error) {
	s, token, err := m.Prepare(ctx, r, t, userID, connection, authTime, methods...)
	if err != nil {
		return nil, err
	}
	if err = m.Commit(ctx, w, r, t, s, token); err != nil {
		return nil, err
	}
	return s, nil
}

// Prepare builds first-factor evidence without creating a session or cookie.
func (m *Manager) Prepare(ctx context.Context, r *http.Request, t *store.Tenant, userID, connection string, authTime time.Time, methods ...store.AuthMethod) (*store.LoginSession, string, error) {
	now := m.now()
	ip, ua := httpx.RecordedIP(r, m.TrustProxyHeaders), r.UserAgent()
	mode := t.SessionCookieMode
	if mode == "" {
		mode = "persistent"
	}
	absolute, idle := lifetimes(t, mode)
	token := secrets.RandomString(43)
	if len(methods) > 0 {
		if cap, ok := m.Store.(store.WebAuthnSupporter); ok {
			if err := cap.CheckWebAuthnSupport(ctx); err != nil {
				if !errors.Is(err, store.ErrWebAuthnUnavailable) {
					return nil, "", err
				}
				methods = nil
			} else if !cap.WebAuthnSupported() {
				methods = nil
			}
		}
	}
	methods = slices.Clone(methods)
	for i := range methods {
		if methods[i].At.IsZero() {
			methods[i].At = authTime.UTC()
		}
	}
	s := &store.LoginSession{
		AuthMethods:     methods,
		Origin:          requestOrigin(r),
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
	return s, token, nil
}

// Commit persists prepared evidence. The caller owns the transaction and must
// buffer the response cookie until that transaction has committed.
// CommitOption adjusts a session after its lifetimes are computed and
// before it is stored and its cookie set (Plan 40 api.session effects).
type CommitOption func(*store.LoginSession)

func (m *Manager) Commit(ctx context.Context, w http.ResponseWriter, r *http.Request, t *store.Tenant, s *store.LoginSession, token string, opts ...CommitOption) error {
	// The SSO lifetime starts when the session is created. Authentication evidence
	// retains the original first-factor time and methods across slow MFA/consent.
	now := m.now()
	absolute, idle := lifetimes(t, s.CookieMode)
	s.ExpiresAt = expiry(now, absolute)
	s.IdleExpiresAt = minTime(expiry(now, idle), s.ExpiresAt)
	s.CreatedAt = now
	s.UpdatedAt = now
	s.LastInteractedAt = now
	for _, opt := range opts {
		opt(s)
	}

	if old, err := r.Cookie(CookieName); err == nil && old.Value != "" {
		previous, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(old.Value))
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil {
			if err = m.Store.Sessions().Delete(ctx, t.ID, previous.ID); err != nil {
				return err
			}
		}
	}
	if err := m.Store.Sessions().Create(ctx, s); err != nil {
		return err
	}
	writeCookie(w, token, s)
	return nil
}

// Reissue rewrites the request's session cookie for s after its expiry or
// cookie mode changed. The cookie must be s's own; otherwise nothing is
// written.
func (m *Manager) Reissue(w http.ResponseWriter, r *http.Request, s *store.LoginSession) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" || secrets.HashToken(c.Value) != s.TokenHash {
		return
	}
	writeCookie(w, c.Value, s)
}

func writeCookie(w http.ResponseWriter, token string, s *store.LoginSession) {
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
	if s.CookieMode == "non-persistent" {
		cookie.Expires = time.Time{}
	}
	http.SetCookie(w, cookie)
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
	if err := m.EndPending(ctx, w, r, t); err != nil {
		return nil, err
	}

	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode,
	})
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s, err := m.Store.Sessions().GetByTokenHash(ctx, t.ID, secrets.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) || err == nil && !sameOrigin(r, s) {
		// Another public origin's session is not this request's session; it
		// is neither extended nor ended here.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ended := false
	err = m.Store.WithTx(ctx, func(tx store.Store) error {
		if m.OnEnd != nil {
			if _, err := tx.Tenants().Get(ctx, t.ID); err != nil {
				return err
			}
		}
		current, err := tx.Sessions().GetForUpdate(ctx, t.ID, s.ID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := tx.Sessions().Delete(ctx, t.ID, s.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if m.OnEnd != nil {
			if err := m.OnEnd(ctx, tx, current); err != nil {
				return err
			}
		}
		ended = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !ended {
		return nil, nil
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
	if errors.Is(err, store.ErrNotFound) || err == nil && !sameOrigin(r, s) {
		// Another public origin's session is not this request's session; it
		// is neither extended nor ended here.
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

// requestOrigin is the resolved public origin of r ("" outside tenant routing).
func requestOrigin(r *http.Request) string {
	if res, ok := tenant.FromContext(r.Context()); ok {
		return res.Origin()
	}
	return ""
}

// sameOrigin reports whether session s may be used on r's public origin; a
// legacy session without an origin belongs to the canonical origin.
func sameOrigin(r *http.Request, s *store.LoginSession) bool {
	res, ok := tenant.FromContext(r.Context())
	return !ok || res.CheckOrigin(s.Origin) == nil
}

// AddMethod appends a performed authentication without overwriting concurrent
// session writes. Legacy plugins explicitly lacking webauthn.v1 omit methods.
func (m *Manager) AddMethod(ctx context.Context, s *store.LoginSession, method store.AuthMethod) error {
	if s == nil {
		return store.ErrNotFound
	}
	if cap, ok := m.Store.(store.WebAuthnSupporter); ok {
		if err := cap.CheckWebAuthnSupport(ctx); err != nil {
			if errors.Is(err, store.ErrWebAuthnUnavailable) {
				return nil
			}
			return err
		}
		if !cap.WebAuthnSupported() {
			return nil
		}
	}
	if method.At.IsZero() {
		method.At = m.now()
	}
	if err := m.Store.Sessions().AddMethod(ctx, s.TenantID, s.ID, method); err != nil {
		return err
	}
	s.AuthMethods = append(s.AuthMethods, method)
	return nil
}

// AddClientOrganization binds the latest validated authorization context. Old
// plugins may retain legacy participation only when no logout template needs it.
func (m *Manager) AddClientOrganization(ctx context.Context, s *store.LoginSession, client *store.Client, orgID string) error {
	repo, ok := m.Store.Sessions().(store.SessionOrganizationRecorder)
	if !ok {
		if client.OIDCLogout != nil {
			return store.ErrOIDCLogoutUnavailable
		}
		return m.AddClient(ctx, s, client.ClientID)
	}
	err := repo.RecordClientOrganization(ctx, s.TenantID, s.ID, client.ClientID, orgID)
	if errors.Is(err, store.ErrOIDCLogoutUnavailable) && client.OIDCLogout == nil {
		return m.AddClient(ctx, s, client.ClientID)
	}
	if err != nil {
		return err
	}
	if !slices.Contains(s.ClientIDs, client.ClientID) {
		s.ClientIDs = append(s.ClientIDs, client.ClientID)
	}
	if s.ClientOrganizations == nil {
		s.ClientOrganizations = map[string]string{}
	}
	s.ClientOrganizations[client.ClientID] = orgID
	return nil
}

// CapActionLimits caps stored and prospective sessions against the deadlines
// observed by the Action and today's policy for the selected cookie mode.
func CapActionLimits(t *store.Tenant, s *store.LoginSession, observed *store.LoginSession, now time.Time) {
	if observed != nil {
		if !observed.ExpiresAt.IsZero() {
			s.ExpiresAt = minTime(s.ExpiresAt, observed.ExpiresAt)
		}
		if !observed.IdleExpiresAt.IsZero() {
			s.IdleExpiresAt = minTime(s.IdleExpiresAt, observed.IdleExpiresAt)
		}
	}
	absolute, idle := lifetimes(t, s.CookieMode)
	start := s.CreatedAt
	if start.IsZero() {
		start = now
	}
	last := s.LastInteractedAt
	if last.IsZero() {
		last = now
	}
	s.ExpiresAt = minTime(s.ExpiresAt, expiry(start, absolute))
	s.IdleExpiresAt = minTime(s.IdleExpiresAt, expiry(last, idle))
	s.IdleExpiresAt = minTime(s.IdleExpiresAt, s.ExpiresAt)
}

type endReasonKey struct{}

func WithEndReason(ctx context.Context, reason string) context.Context {
	return context.WithValue(ctx, endReasonKey{}, reason)
}
func EndReason(ctx context.Context) string { v, _ := ctx.Value(endReasonKey{}).(string); return v }

// RevokeFromAction keeps offline-family revocation effective even if ordinary
// logout removed the session during the Action. Callbacks use the same tx.
func RevokeFromAction(ctx context.Context, st store.Store, sess *store.LoginSession, preserve bool, at time.Time, onEnd func(context.Context, store.Store, *store.LoginSession) error) error {
	if sess == nil {
		return nil
	}
	ctx = WithEndReason(ctx, "session-revoked")
	return st.WithTx(ctx, func(tx store.Store) error {
		if _, e := tx.Tenants().Get(ctx, sess.TenantID); e != nil {
			return e
		}
		current, e := tx.Sessions().GetForUpdate(ctx, sess.TenantID, sess.ID)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return e
		}
		owners, e := tx.RefreshTokens().SessionOwners(ctx, sess.TenantID, sess.ID)
		if e != nil {
			return e
		}
		owners = append(owners, sess.UserID)
		if current != nil {
			owners = append(owners, current.UserID)
		}
		slices.Sort(owners)
		owners = slices.Compact(owners)
		for _, uid := range owners {
			if _, e := tx.Users().GetForUpdate(ctx, sess.TenantID, uid); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
		}
		if !preserve {
			if _, e := tx.RefreshTokens().RevokeBySession(ctx, sess.TenantID, sess.ID, at); e != nil {
				return e
			}
		}
		for _, uid := range owners {
			if _, e := tx.Users().BumpVersion(ctx, sess.TenantID, uid); e != nil && !errors.Is(e, store.ErrNotFound) {
				return e
			}
		}
		if current != nil {
			if e := tx.Sessions().Delete(ctx, sess.TenantID, sess.ID); e != nil {
				return e
			}
			if onEnd != nil {
				return onEnd(ctx, tx, current)
			}
		}
		return nil
	})
}
