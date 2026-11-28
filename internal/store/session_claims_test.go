package store_test

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"strings"
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

func TestSessionClaimsTotalBoundAndClear(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	_ = st.Sessions().Create(ctx, &store.LoginSession{TenantID: "t", ID: "s", TokenHash: "h"})
	for i := range 20 {
		_, err := store.SetSessionClaims(ctx, st, "t", "s", fmt.Sprint(i), `{"urn:value":"`+strings.Repeat("x", 90000)+`"}`)
		if i < 10 && err != nil {
			t.Fatal(err)
		}
		if err != nil {
			break
		}
		if i == 19 {
			t.Fatal("unbounded total session claims")
		}
	}
	_, err := store.SetSessionClaims(ctx, st, "t", "s", "0", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := st.Sessions().Get(ctx, "t", "s")
	if _, ok := s.UserinfoClaims["0"]; ok {
		t.Fatal("empty client entry retained")
	}
}
