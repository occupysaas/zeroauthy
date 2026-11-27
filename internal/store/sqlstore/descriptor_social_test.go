package sqlstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// TestSQLSocialIdentityIndex indexes a Plan 39b descriptor identity by its raw
// provider subject and provisions one user under concurrent first logins.
func TestSQLSocialIdentityIndex(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpen(t, dsn)
			if err := a.SocialFederationSupported(ctx); err != nil {
				t.Fatal(err)
			}
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := a.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "con_fb", Name: "fb", Strategy: "amazon"}); err != nil {
				t.Fatal(err)
			}
			handles := []*Store{a, b}
			const n = 6
			outcomes := make(chan error, n)
			for i := range n {
				go func() {
					outcomes <- handles[i%2].Users().Create(ctx, &store.User{TenantID: "t", UserID: "amazon|amzn1.account.X",
						Identities: []store.Identity{{Connection: "fb", Provider: "amazon", UserID: "amzn1.account.X"}}})
				}()
			}
			won := 0
			for range n {
				if err := <-outcomes; err == nil {
					won++
				} else if !errors.Is(err, store.ErrConflict) {
					t.Fatalf("provision error %v", err)
				}
			}
			if won != 1 {
				t.Fatalf("%d users provisioned", won)
			}
			u, err := b.Users().FindByIdentity(ctx, "t", "con_fb", "amzn1.account.X")
			if err != nil || u.UserID != "amazon|amzn1.account.X" {
				t.Fatalf("owner %+v %v", u, err)
			}
		})
	}
}
