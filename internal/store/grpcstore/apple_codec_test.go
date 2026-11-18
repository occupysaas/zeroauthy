package grpcstore

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestAppleProviderDataRoundTrip(t *testing.T) {
	c := serve(t, memory.New())
	defer c.Close()
	ctx := context.Background()
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "apple", Name: "apple", Strategy: "apple"}); err != nil {
		t.Fatal(err)
	}
	u := &store.User{TenantID: "t", UserID: "apple|sub", Identities: []store.Identity{{Connection: "apple", Provider: "apple", UserID: "sub", ProviderData: map[string]any{"is_private_email": true}}}}
	if err := c.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := c.Users().FindByIdentity(ctx, "t", "apple", "sub")
	if err != nil {
		t.Fatal(err)
	}
	if got.Identities[0].Linked() || got.Identities[0].ProviderData["is_private_email"] != true {
		t.Fatalf("provider data lost: %+v", got.Identities)
	}
	now := time.Now().UTC()
	a := &store.FederationAttempt{TenantID: "t", StateHash: "s", ConnectionID: "apple", Status: store.AttemptPending, CreatedAt: now, ExpiresAt: now.Add(time.Minute), Endpoints: store.FederationEndpoints{PKCES256: true}}
	if err := c.Federation().CreateAttempt(ctx, a); err != nil {
		t.Fatal(err)
	}
	again, err := c.Federation().GetAttempt(ctx, "t", "s")
	if err != nil || !again.Endpoints.PKCES256 {
		t.Fatalf("snapshot %+v %v", again, err)
	}
	roundTrip(t, "Apple snapshot", &store.FederationAttempt{Endpoints: store.FederationEndpoints{PKCES256: true}}, attemptToPB, attemptFromPB)
}
