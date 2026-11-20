package sqlstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSQLGitHubIdentityIndex(t *testing.T) {
	ctx := context.Background()
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			dsn := mk(t)
			a := mustOpen(t, dsn)
			b := mustOpen(t, dsn)
			if err := a.GitHubFederationSupported(ctx); err != nil {
				t.Fatal(err)
			}
			if err := a.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := a.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "con_gh", Name: "gh", Strategy: "github"}); err != nil {
				t.Fatal(err)
			}

			// Direct index put, find and delete for a github key.
			if err := a.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|owner"}); err != nil {
				t.Fatal(err)
			}
			key := store.FederatedIdentityKey{TenantID: "t", ConnectionID: "con_gh", Subject: "7"}
			if err := a.Federation().PutIdentity(ctx, key, "auth0|owner"); err != nil {
				t.Fatal(err)
			}
			if u, err := b.Users().FindByIdentity(ctx, "t", "con_gh", "7"); err != nil || u.UserID != "auth0|owner" {
				t.Fatalf("find %+v %v", u, err)
			}
			if err := a.Federation().PutIdentity(ctx, key, "auth0|other"); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("foreign put %v", err)
			}
			if err := a.Federation().DeleteIdentity(ctx, key, "auth0|owner"); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Users().FindByIdentity(ctx, "t", "con_gh", "7"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("deleted identity still found: %v", err)
			}

			// Concurrent first logins of one GitHub account provision one user.
			handles := []*Store{a, b}
			const n = 6
			outcomes := make(chan error, n)
			for i := range n {
				go func() {
					outcomes <- handles[i%2].Users().Create(ctx, &store.User{TenantID: "t", UserID: "github|42",
						Identities: []store.Identity{{Connection: "gh", Provider: "github", UserID: "42"}}})
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
			u, err := b.Users().FindByIdentity(ctx, "t", "con_gh", "42")
			if err != nil || u.UserID != "github|42" {
				t.Fatalf("owner %+v %v", u, err)
			}

			// A non-canonical subject is never indexed.
			err = a.Users().Create(ctx, &store.User{TenantID: "t", UserID: "github|042",
				Identities: []store.Identity{{Connection: "gh", Provider: "github", UserID: "042"}}})
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("non-canonical create %v", err)
			}
		})
	}
}
