package sqlstore

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestAppleIdentityAndSnapshotRoundTrip(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			s := fresh(t)
			ctx := context.Background()
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := s.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "a", Name: "apple", Strategy: "apple"}); err != nil {
				t.Fatal(err)
			}
			u := &store.User{TenantID: "t", UserID: "apple|raw|sub", Identities: []store.Identity{{Connection: "apple", Provider: "apple", UserID: "raw|sub", ProviderData: map[string]any{"is_private_email": true, "real_user_status": float64(2)}}}}
			if err := s.Users().Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			got, err := s.Users().FindByIdentity(ctx, "t", "a", "raw|sub")
			if err != nil {
				t.Fatal(err)
			}
			if got.Identities[0].Linked() || got.Identities[0].ProviderData["is_private_email"] != true || got.Identities[0].ProviderData["real_user_status"] != float64(2) {
				t.Fatalf("roundtrip: %+v", got.Identities)
			}
			got.Identities[0].ProviderData["is_private_email"] = false
			if err := s.Users().Update(ctx, got); err != nil {
				t.Fatal(err)
			}
			got, err = s.Users().Get(ctx, "t", u.UserID)
			if err != nil || got.Identities[0].ProviderData["is_private_email"] != false {
				t.Fatalf("update: %+v %v", got, err)
			}
			now := time.Now().UTC()
			a := &store.FederationAttempt{TenantID: "t", StateHash: "state", TransactionID: "tx", ConnectionID: "a", Origin: "https://login.example", CallbackURL: "https://login.example/login/callback", Endpoints: store.FederationEndpoints{PKCES256: true, TokenAuthMethod: "client_secret_post"}, Status: store.AttemptPending, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
			if err := s.Federation().CreateAttempt(ctx, a); err != nil {
				t.Fatal(err)
			}
			again, err := s.Federation().GetAttempt(ctx, "t", "state")
			if err != nil || !again.Endpoints.PKCES256 {
				t.Fatalf("snapshot: %+v %v", again, err)
			}
		})
	}
}
