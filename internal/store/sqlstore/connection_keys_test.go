package sqlstore

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestConnectionKeys(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store { return fresh(t) }, "ConnectionKeys")
		})
	}
}

func TestMigrationOIDCChannel(t *testing.T) {
	ctx := context.Background()
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			for _, tc := range []struct{ id, extra string }{{"legacy", `{"client_id":"client","scopes":"openid"}`}, {"front", `{"type":"front_channel","client_id":"client"}`}} {
				c := &store.Connection{TenantID: "ten_a", ID: tc.id, Name: tc.id, Strategy: "oidc"}
				if err := json.Unmarshal([]byte(tc.extra), &c.Extra); err != nil {
					t.Fatal(err)
				}
				if err := s.Connections().Create(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.backfillOIDCChannel(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.backfillOIDCChannel(ctx); err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ id, channel string }{{"legacy", "back_channel"}, {"front", "front_channel"}} {
				c, err := s.Connections().Get(ctx, "ten_a", tc.id)
				if err != nil || c.Extra["type"] != tc.channel || c.Extra["client_id"] != "client" {
					t.Fatal(c, err)
				}
			}
		})
	}
}
