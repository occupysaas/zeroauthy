package grpcstore

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestSessionLimits round-trips Plan 40's SetLimits through the plugin over
// the memory and SQLite backends.
func TestSessionLimits(t *testing.T) {
	for name, c := range map[string]*Client{"memory": inProcess(t), "sqlite": inProcessSQLite(t)} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
			if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			s := &store.LoginSession{TenantID: "t", ID: "s1", TokenHash: "h1", UserID: "auth0|u", Connection: "db", AuthenticatedAt: now,
				ExpiresAt: now.Add(72 * time.Hour), IdleExpiresAt: now.Add(24 * time.Hour), CreatedAt: now, UpdatedAt: now, LastInteractedAt: now, CookieMode: "persistent"}
			if err := c.Sessions().Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			got, err := store.SetSessionLimits(ctx, c, "t", "s1", now.Add(time.Hour), now.Add(30*time.Minute), "non-persistent")
			if err != nil {
				t.Fatal(err)
			}
			if !got.ExpiresAt.Equal(now.Add(time.Hour)) || !got.IdleExpiresAt.Equal(now.Add(30*time.Minute)) || got.CookieMode != "non-persistent" {
				t.Fatalf("session %+v", got)
			}
			if _, err := store.SetSessionLimits(ctx, c, "t", "missing", now, now, ""); err == nil {
				t.Fatal("missing session updated")
			}
		})
	}
}
