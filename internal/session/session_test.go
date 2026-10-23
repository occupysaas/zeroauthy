package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup() (*Manager, *clock, *store.Tenant) {
	c := &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	return &Manager{Store: memory.New(), Now: c.now}, c, &store.Tenant{ID: "ten_a", Name: "a"}
}

func requestWith(cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "https://a.test/authorize", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func TestStartAndCurrent(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	ck := cookies[0]
	if ck.Name != CookieName || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode || ck.Path != "/" || len(ck.Value) < 40 {
		t.Fatalf("cookie = %+v", ck)
	}
	if s.TokenHash != secrets.HashToken(ck.Value) || s.TokenHash == ck.Value {
		t.Fatal("session must store only the cookie hash")
	}
	if !s.ExpiresAt.Equal(c.t.Add(DefaultLifetime)) || !s.IdleExpiresAt.Equal(c.t.Add(DefaultIdleLifetime)) {
		t.Fatalf("expiry = %v / %v", s.ExpiresAt, s.IdleExpiresAt)
	}

	c.t = c.t.Add(time.Hour)
	got, err := m.Current(ctx, requestWith(cookies), tn)
	if err != nil || got == nil || got.ID != s.ID {
		t.Fatalf("Current = %+v, %v", got, err)
	}
	if !got.IdleExpiresAt.Equal(c.t.Add(DefaultIdleLifetime)) {
		t.Fatalf("idle expiry not slid: %v", got.IdleExpiresAt)
	}

	other := &store.Tenant{ID: "ten_b"}
	if got, err := m.Current(ctx, requestWith(cookies), other); err != nil || got != nil {
		t.Fatalf("session visible to another tenant: %+v, %v", got, err)
	}
	if got, err := m.Current(ctx, requestWith([]*http.Cookie{{Name: CookieName, Value: "forged"}}), tn); err != nil || got != nil {
		t.Fatalf("forged cookie accepted: %+v, %v", got, err)
	}
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	tn.SessionLifetime, tn.IdleSessionLifetime = 7200, 1800

	rec := httptest.NewRecorder()
	if _, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()

	c.t = c.t.Add(31 * time.Minute) // idle timeout passed
	got, err := m.Current(ctx, requestWith(cookies), tn)
	if err != nil || got != nil {
		t.Fatalf("idle-expired session: Current = %+v, %v; want nil, nil", got, err)
	}

	rec = httptest.NewRecorder()
	if _, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t); err != nil {
		t.Fatal(err)
	}
	cookies = rec.Result().Cookies()
	// Stay active: each call must still return the session while it is
	// before the absolute limit (t=25, 50, 75, 100 min of 120 min).
	for i := 0; i < 4; i++ {
		c.t = c.t.Add(25 * time.Minute)
		got, err := m.Current(ctx, requestWith(cookies), tn)
		if err != nil || got == nil {
			t.Fatalf("active session at +%v: Current = %+v, %v", c.t, got, err)
		}
		if got.IdleExpiresAt.After(got.ExpiresAt) {
			t.Fatalf("idle expiry %v passed absolute expiry %v", got.IdleExpiresAt, got.ExpiresAt)
		}
	}
	// Last valid iteration: the idle slide (100+30) is capped at the absolute expiry (120).
	// Now pass the absolute limit (t=125 min).
	c.t = c.t.Add(25 * time.Minute)
	got, err = m.Current(ctx, requestWith(cookies), tn)
	if err != nil || got != nil {
		t.Fatalf("session past absolute lifetime: Current = %+v, %v; want nil, nil", got, err)
	}
}

func TestCurrentDeletesExpiredRecord(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()

	c.t = c.t.Add(DefaultIdleLifetime + time.Minute)
	if got, err := m.Current(ctx, requestWith(cookies), tn); err != nil || got != nil {
		t.Fatalf("expired session: Current = %+v, %v; want nil, nil", got, err)
	}
	if _, err := m.Store.Sessions().GetByTokenHash(ctx, tn.ID, s.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired record still stored: err = %v", err)
	}
}

// notFoundOnTouch simulates a session deleted (e.g. by logout) between
// Current's read and its sliding write.
type notFoundOnTouch struct{ store.Store }

func (s notFoundOnTouch) Sessions() store.Sessions { return notFoundSessions{s.Store.Sessions()} }

type notFoundSessions struct{ store.Sessions }

func (notFoundSessions) Touch(context.Context, string, string, time.Time, time.Time, string, string) error {
	return store.ErrNotFound
}

func TestCurrentToleratesConcurrentDelete(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	if _, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t); err != nil {
		t.Fatal(err)
	}
	m.Store = notFoundOnTouch{m.Store}

	got, err := m.Current(ctx, requestWith(rec.Result().Cookies()), tn)
	if err != nil || got != nil {
		t.Fatalf("Current after concurrent delete = %+v, %v; want nil, nil", got, err)
	}
}

func TestStartReplacesExistingSession(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	if _, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t); err != nil {
		t.Fatal(err)
	}
	first := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	second, err := m.Start(ctx, rec, requestWith(first), tn, "auth0|2", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.Current(ctx, requestWith(first), tn); err != nil || got != nil {
		t.Fatalf("old session survived a new login: %+v, %v", got, err)
	}
	got, err := m.Current(ctx, requestWith(rec.Result().Cookies()), tn)
	if err != nil || got == nil || got.ID != second.ID || got.UserID != "auth0|2" {
		t.Fatalf("new session = %+v, %v; want user auth0|2", got, err)
	}
}

func TestAddClient(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddClient(ctx, s, "spa"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddClient(ctx, s, "spa"); err != nil {
		t.Fatal(err)
	}
	got, err := m.Current(ctx, requestWith(rec.Result().Cookies()), tn)
	if err != nil || got == nil {
		t.Fatalf("Current = %+v, %v", got, err)
	}
	if len(got.ClientIDs) != 1 || got.ClientIDs[0] != "spa" {
		t.Fatalf("clients = %v", got.ClientIDs)
	}
}

func TestEnd(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	ended, err := m.End(ctx, rec, requestWith(cookies), tn)
	if err != nil || ended == nil || ended.ID != s.ID {
		t.Fatalf("End = %+v, %v", ended, err)
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != CookieName || cleared[0].MaxAge >= 0 || !cleared[0].Secure ||
		!cleared[0].HttpOnly || cleared[0].SameSite != http.SameSiteNoneMode || cleared[0].Path != "/" {
		t.Fatalf("clearing cookie = %+v", cleared)
	}
	if got, err := m.Current(ctx, requestWith(cookies), tn); err != nil || got != nil {
		t.Fatalf("session survived End: %+v, %v", got, err)
	}
	// Ending again, or without a cookie, is not an error and still clears.
	rec = httptest.NewRecorder()
	if ended, err := m.End(ctx, rec, requestWith(cookies), tn); err != nil || ended != nil || len(rec.Result().Cookies()) != 1 {
		t.Fatalf("second End = %+v, %v, %v", ended, err, rec.Result().Cookies())
	}
	if ended, err := m.End(ctx, httptest.NewRecorder(), requestWith(nil), tn); err != nil || ended != nil {
		t.Fatalf("End without cookie = %+v, %v", ended, err)
	}
}

func TestLookupDoesNotSlide(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	c.t = c.t.Add(time.Hour)
	got, err := m.Lookup(ctx, requestWith(cookies), tn)
	if err != nil || got == nil || got.ID != s.ID || !got.IdleExpiresAt.Equal(s.IdleExpiresAt) {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	stored, _ := m.Store.Sessions().GetByTokenHash(ctx, tn.ID, s.TokenHash)
	if !stored.IdleExpiresAt.Equal(s.IdleExpiresAt) {
		t.Fatal("Lookup extended the idle expiry")
	}
	c.t = s.IdleExpiresAt
	if got, err := m.Lookup(ctx, requestWith(cookies), tn); err != nil || got != nil {
		t.Fatalf("expired Lookup = %+v, %v", got, err)
	}
	if got, err := m.Lookup(ctx, requestWith(nil), tn); err != nil || got != nil {
		t.Fatalf("Lookup without cookie = %+v, %v", got, err)
	}
}

func TestDeviceRecorded(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	m.TrustProxyHeaders = true
	req := func(cookies []*http.Cookie, ip, ua string) *http.Request {
		r := requestWith(cookies)
		r.Header.Set("X-Forwarded-For", ip)
		r.Header.Set("User-Agent", ua)
		return r
	}
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, req(nil, "203.0.113.7", "agent-1"), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.InitialIP != "203.0.113.7" || stored.InitialUserAgent != "agent-1" || stored.LastIP != "203.0.113.7" ||
		stored.LastUserAgent != "agent-1" || !stored.UpdatedAt.Equal(c.t) || !stored.LastInteractedAt.Equal(c.t) {
		t.Fatalf("created session = %+v", stored)
	}

	c.t = c.t.Add(time.Hour)
	if _, err := m.Current(ctx, req(rec.Result().Cookies(), "198.51.100.9", "agent-2"), tn); err != nil {
		t.Fatal(err)
	}
	stored, _ = m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if stored.InitialIP != "203.0.113.7" || stored.InitialUserAgent != "agent-1" {
		t.Errorf("initial device changed: %+v", stored)
	}
	if stored.LastIP != "198.51.100.9" || stored.LastUserAgent != "agent-2" ||
		!stored.UpdatedAt.Equal(c.t) || !stored.LastInteractedAt.Equal(c.t) || !stored.CreatedAt.Before(c.t) {
		t.Errorf("touched session = %+v", stored)
	}
}

// A client IP that is not an address (a hostile X-Forwarded-For) is
// stored as "", on creation and on touch.
func TestDeviceIPMustBeAnAddress(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	m.TrustProxyHeaders = true
	req := func(cookies []*http.Cookie, ip string) *http.Request {
		r := requestWith(cookies)
		r.Header.Set("X-Forwarded-For", ip)
		return r
	}
	rec := httptest.NewRecorder()
	s, err := m.Start(ctx, rec, req(nil, "<b>not an ip</b>"), tn, "auth0|1", "Database", c.t)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := m.Store.Sessions().Get(ctx, tn.ID, s.ID)
	if stored.InitialIP != "" || stored.LastIP != "" {
		t.Fatalf("created session IPs = %q, %q", stored.InitialIP, stored.LastIP)
	}
	c.t = c.t.Add(time.Minute)
	if _, err := m.Current(ctx, req(rec.Result().Cookies(), "2001:DB8::9"), tn); err != nil {
		t.Fatal(err)
	}
	if stored, _ = m.Store.Sessions().Get(ctx, tn.ID, s.ID); stored.LastIP != "2001:db8::9" {
		t.Errorf("touched LastIP = %q", stored.LastIP)
	}
	c.t = c.t.Add(time.Minute)
	if _, err := m.Current(ctx, req(rec.Result().Cookies(), "1.2.3.4\x00x"), tn); err != nil {
		t.Fatal(err)
	}
	if stored, _ = m.Store.Sessions().Get(ctx, tn.ID, s.ID); stored.LastIP != "" {
		t.Errorf("hostile touch LastIP = %q", stored.LastIP)
	}
}

func TestTenantSessionCookiePolicy(t *testing.T) {
	for _, mode := range []string{"persistent", "non-persistent"} {
		t.Run(mode, func(t *testing.T) {
			m, c, tn := setup()
			tn.SessionCookieMode = mode
			tn.SessionLifetime = 3600
			tn.EphemeralSessionLifetime = 3600
			tn.IdleSessionLifetime = 1800
			tn.IdleEphemeralSessionLifetime = 1200
			rec := httptest.NewRecorder()
			s, err := m.Start(context.Background(), rec, requestWith(nil), tn, "u", "db", c.t)
			if err != nil {
				t.Fatal(err)
			}
			if s.CookieMode != mode || !s.ExpiresAt.Equal(c.t.Add(time.Hour)) {
				t.Fatalf("session: %+v", s)
			}
			ck := rec.Result().Cookies()[0]
			if mode == "non-persistent" && (!ck.Expires.IsZero() || ck.MaxAge != 0) {
				t.Fatalf("transient cookie: %+v", ck)
			}
			if mode == "persistent" && !ck.Expires.Equal(s.ExpiresAt) {
				t.Fatalf("persistent cookie: %+v", ck)
			}
			// Switching the tenant default does not switch an existing session's mode.
			tn.SessionCookieMode = "persistent"
			tn.IdleSessionLifetime = 900
			tn.IdleEphemeralSessionLifetime = 300
			tn.SessionLifetime = 7200
			tn.EphemeralSessionLifetime = 7200
			c.t = c.t.Add(time.Minute)
			got, err := m.Current(context.Background(), requestWith(rec.Result().Cookies()), tn)
			if err != nil || got == nil {
				t.Fatalf("Current: %+v %v", got, err)
			}
			idle := 900
			if mode == "non-persistent" {
				idle = 300
			}
			if !got.IdleExpiresAt.Equal(c.t.Add(time.Duration(idle)*time.Second)) || !got.ExpiresAt.Equal(s.ExpiresAt) {
				t.Fatalf("touch changed lifetime/mode: %+v", got)
			}
		})
	}
}

func TestTenantSessionHugeLifetime(t *testing.T) {
	m, c, tn := setup()
	tn.SessionLifetime = int(^uint(0) >> 1)
	tn.IdleSessionLifetime = tn.SessionLifetime
	rec := httptest.NewRecorder()
	s, err := m.Start(context.Background(), rec, requestWith(nil), tn, "u", "db", c.t)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	if !s.ExpiresAt.Equal(want) || !s.IdleExpiresAt.Equal(want) {
		t.Fatalf("overflow: %+v", s)
	}
}

func TestTenantSessionEphemeralDefaultsAndExpiry(t *testing.T) {
	m, c, tn := setup()
	tn.SessionCookieMode = "non-persistent"
	rec := httptest.NewRecorder()
	s, err := m.Start(context.Background(), rec, requestWith(nil), tn, "u", "db", c.t)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ExpiresAt.Equal(c.t.Add(72*time.Hour)) || !s.IdleExpiresAt.Equal(c.t.Add(24*time.Hour)) {
		t.Fatalf("ephemeral defaults: %+v", s)
	}
	c.t = c.t.Add(24 * time.Hour)
	if got, err := m.Lookup(context.Background(), requestWith(rec.Result().Cookies()), tn); err != nil || got != nil {
		t.Fatalf("expired transient session: %+v %v", got, err)
	}
}

func TestTenantSessionLegacyCookieMode(t *testing.T) {
	m, c, tn := setup()
	tn.SessionCookieMode = "non-persistent"
	tn.IdleSessionLifetime = 1800
	tn.IdleEphemeralSessionLifetime = 300
	s := &store.LoginSession{TenantID: tn.ID, ID: "legacy", TokenHash: secrets.HashToken("legacy"), UserID: "u", ExpiresAt: c.t.Add(time.Hour), IdleExpiresAt: c.t.Add(time.Hour)}
	if err := m.Store.Sessions().Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	got, err := m.Current(context.Background(), requestWith([]*http.Cookie{{Name: CookieName, Value: "legacy"}}), tn)
	if err != nil || got == nil || !got.IdleExpiresAt.Equal(c.t.Add(30*time.Minute)) {
		t.Fatalf("legacy session changed mode: %+v %v", got, err)
	}
}
