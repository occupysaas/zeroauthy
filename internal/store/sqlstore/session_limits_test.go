package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSQLSessionLimits(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := mustOpen(t, mk(t))
			now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := s.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "s1", TokenHash: "h1", UserID: "auth0|u", Connection: "db",
				AuthenticatedAt: now, ExpiresAt: now.Add(72 * time.Hour), IdleExpiresAt: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now, LastInteractedAt: now}); err != nil {
				t.Fatal(err)
			}
			got, err := store.SetSessionLimits(ctx, s, "t", "s1", now.Add(time.Hour), now.Add(time.Minute), "non-persistent")
			if err != nil || !got.ExpiresAt.Equal(now.Add(time.Hour)) || !got.IdleExpiresAt.Equal(now.Add(time.Minute)) || got.CookieMode != "non-persistent" {
				t.Fatalf("%+v %v", got, err)
			}
			if _, err := store.SetSessionLimits(ctx, s, "t", "nope", now, now, ""); err == nil {
				t.Fatal("missing session updated")
			}
		})
	}
}
