package store_test

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
)

type oldClaimStore struct{ store.Store }
type oldClaimSessions struct{ store.Sessions }

func (s oldClaimStore) Sessions() store.Sessions { return oldClaimSessions{s.Store.Sessions()} }
func TestEmptySessionClaimsOldPlugin(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "h"}); err != nil {
		t.Fatal(err)
	}
	old := oldClaimStore{st}
	if _, err := store.SetSessionClaims(ctx, old, "t", "s", "client", `{}`); err != nil {
		t.Fatalf("empty effects broke an old plugin: %v", err)
	}
	if _, err := store.SetSessionClaims(ctx, old, "t", "s", "client", `{"urn:custom":true}`); err == nil {
		t.Fatal("unsupported write accepted")
	}
}
