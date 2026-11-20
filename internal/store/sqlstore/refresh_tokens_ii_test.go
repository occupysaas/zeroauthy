package sqlstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Exercise the migrated tuple index at its maximum byte widths, including
// audiences which share the indexed prefix but identify different resources.
func TestRefreshTupleIndexFullValues(t *testing.T) {
	for dialect, fresh := range dialectsUnderTest(t) {
		t.Run(dialect, func(t *testing.T) {
			ctx := context.Background()
			repo := fresh(t).RefreshTokens()
			tenant := strings.Repeat("t", 64)
			user := strings.Repeat("😀", 320) // VARBINARY(1280) on MySQL.
			client := strings.Repeat("😀", 255)
			audience := strings.Repeat("😀", 128)
			var tokens []*store.RefreshToken
			for _, suffix := range []string{"a", "b"} {
				rt := &store.RefreshToken{
					TenantID: tenant, ID: suffix, TokenHash: "hash-" + suffix, FamilyID: suffix,
					UserID: user, ClientID: client, Audience: audience + suffix,
					CreatedAt: time.Unix(1, 0), Access: "offline",
				}
				if err := repo.Create(ctx, rt); err != nil {
					t.Fatal(err)
				}
				tokens = append(tokens, rt)
			}
			n, err := repo.RevokeByUserClient(ctx, tenant, user, client, audience+"a", time.Unix(2, 0))
			if err != nil || n != 1 {
				t.Fatalf("revoke exact audience: count=%d, err=%v", n, err)
			}
			for i, rt := range tokens {
				got, err := repo.Get(ctx, tenant, rt.ID)
				if err != nil {
					t.Fatal(err)
				}
				if got.UserID != user || got.ClientID != client || got.Audience != rt.Audience || (got.RevokedAt != nil) != (i == 0) {
					t.Fatalf("full tuple values or audience isolation lost for token %s", rt.ID)
				}
			}
		})
	}
}
