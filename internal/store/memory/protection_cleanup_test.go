package memory_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
	"time"
)

func TestProtectionLinkedDeletionIsolation(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	now := time.Unix(1000, 0)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}))
	must(st.Connections().Create(ctx, &store.Connection{ID: "c", TenantID: "t", Name: "db", Strategy: store.StrategyDatabase}))
	u := &store.User{TenantID: "t", UserID: "social|root", Email: "other@example.test", Identities: []store.Identity{{Provider: "social", Connection: "social", UserID: "root"}, {Provider: store.StrategyDatabase, Connection: "db", UserID: "collision@example.test", ProfileData: map[string]any{"email": "linked@example.test"}}}}
	must(st.Users().Create(ctx, u))
	for _, alias := range []string{"other@example.test", "collision@example.test", "linked@example.test"} {
		d, err := st.Protection().Reserve(ctx, []store.ProtectionLimit{{Key: store.ProtectionKey{TenantID: "t", Kind: store.ProtectionBruteForce, ConnectionID: "c", Identifier: alias}, Algorithm: "brute-force", Capacity: 1, Lockout: time.Hour}}, now)
		must(err)
		must(st.Protection().Complete(ctx, d.Receipt, "failure", now))
	}
	must(st.Users().Delete(ctx, "t", u.UserID))
	blocks, err := st.Protection().Blocks(ctx, "t", store.ProtectionFilter{}, now)
	must(err)
	seen := map[string]bool{}
	for _, b := range blocks {
		seen[b.Key.Identifier] = true
	}
	if seen["linked@example.test"] || !seen["other@example.test"] || !seen["collision@example.test"] {
		t.Fatalf("deletion crossed identity ownership: %v", seen)
	}
}
