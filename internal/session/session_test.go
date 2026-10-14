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

func (notFoundSessions) Touch(context.Context, string, string, time.Time) error {
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
