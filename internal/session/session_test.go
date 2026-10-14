package session

import (
	"context"
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
	if got, _ := m.Current(ctx, requestWith(cookies), other); got != nil {
		t.Fatal("session visible to another tenant")
	}
	if got, _ := m.Current(ctx, requestWith([]*http.Cookie{{Name: CookieName, Value: "forged"}}), tn); got != nil {
		t.Fatal("forged cookie accepted")
	}
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	tn.SessionLifetime, tn.IdleSessionLifetime = 7200, 1800

	rec := httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	cookies := rec.Result().Cookies()

	c.t = c.t.Add(31 * time.Minute) // idle timeout passed
	if got, _ := m.Current(ctx, requestWith(cookies), tn); got != nil {
		t.Fatal("idle-expired session accepted")
	}

	rec = httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	cookies = rec.Result().Cookies()
	for i := 0; i < 5; i++ { // stay active, but pass the absolute limit
		c.t = c.t.Add(25 * time.Minute)
		_, _ = m.Current(ctx, requestWith(cookies), tn)
	}
	if got, _ := m.Current(ctx, requestWith(cookies), tn); got != nil {
		t.Fatal("session outlived its absolute lifetime")
	}
}

func TestStartReplacesExistingSession(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	first := rec.Result().Cookies()

	rec = httptest.NewRecorder()
	_, _ = m.Start(ctx, rec, requestWith(first), tn, "auth0|2", "Database", c.t)
	if got, _ := m.Current(ctx, requestWith(first), tn); got != nil {
		t.Fatal("old session survived a new login")
	}
}

func TestAddClient(t *testing.T) {
	ctx := context.Background()
	m, c, tn := setup()
	rec := httptest.NewRecorder()
	s, _ := m.Start(ctx, rec, requestWith(nil), tn, "auth0|1", "Database", c.t)
	if err := m.AddClient(ctx, s, "spa"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddClient(ctx, s, "spa"); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Current(ctx, requestWith(rec.Result().Cookies()), tn)
	if len(got.ClientIDs) != 1 || got.ClientIDs[0] != "spa" {
		t.Fatalf("clients = %v", got.ClientIDs)
	}
}
