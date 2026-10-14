package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newClient(tenantID, clientID string) *store.Client {
	exp := ts(48 * time.Hour)
	return &store.Client{
		TenantID: tenantID,
		ClientID: clientID,
		Name:     "App " + clientID,
		AppType:  store.AppTypeNonInteractive,
		Secrets: []store.ClientSecret{
			{Hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA", CreatedAt: ts(0)},
			{Hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdDI$aGFzaDI", CreatedAt: ts(time.Hour), ExpiresAt: &exp},
		},
		TokenEndpointAuthMethod: store.AuthMethodClientSecretPost,
		GrantTypes:              []string{"client_credentials"},
		Callbacks:               []string{"https://app.test/callback"},
		AllowedLogoutURLs:       []string{"https://app.test/"},
		WebOrigins:              []string{"https://app.test"},
		AllowedOrigins:          []string{"https://app.test"},
		RefreshToken:            store.RefreshTokenPolicy{Rotating: true, Leeway: 5, Expiring: true, TokenLifetime: 86400, IdleTokenLifetime: 3600},
		CreatedAt:               ts(0),
	}
}

func testClients(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) {
		s := open(t, newStore)
		want := newClient("ten_a", "c1")
		mustNoErr(t, s.Clients().Create(ctx, want))
		mustErrIs(t, s.Clients().Create(ctx, newClient("ten_a", "c1")), store.ErrConflict)

		got, err := s.Clients().Get(ctx, "ten_a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.Name = "Renamed"
		want.Secrets = want.Secrets[:1]
		mustNoErr(t, s.Clients().Update(ctx, want))
		got, err = s.Clients().Get(ctx, "ten_a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		mustNoErr(t, s.Clients().Delete(ctx, "ten_a", "c1"))
		_, err = s.Clients().Get(ctx, "ten_a", "c1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Clients().Delete(ctx, "ten_a", "c1"), store.ErrNotFound)
		mustErrIs(t, s.Clients().Update(ctx, want), store.ErrNotFound)
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		s := open(t, newStore)
		a := newClient("ten_a", "same-id")
		b := newClient("ten_b", "same-id")
		b.Name = "Tenant B app"
		mustNoErr(t, s.Clients().Create(ctx, a))
		mustNoErr(t, s.Clients().Create(ctx, b))

		got, err := s.Clients().Get(ctx, "ten_b", "same-id")
		mustNoErr(t, err)
		mustEqual(t, got.Name, "Tenant B app")
		_, err = s.Clients().Get(ctx, "ten_c", "same-id")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newClient("ten_a", "c1")
		mustNoErr(t, s.Clients().Create(ctx, in))
		*in.Secrets[1].ExpiresAt = ts(0)
		in.GrantTypes[0] = "mutated"

		got, err := s.Clients().Get(ctx, "ten_a", "c1")
		mustNoErr(t, err)
		mustEqual(t, got, newClient("ten_a", "c1"))
	})

	t.Run("ListOrderedByClientID", func(t *testing.T) {
		s := open(t, newStore)
		for _, id := range []string{"zz", "aa", "mm"} {
			mustNoErr(t, s.Clients().Create(ctx, newClient("ten_a", id)))
		}
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_b", "other")))
		got, err := s.Clients().List(ctx, "ten_a")
		mustNoErr(t, err)
		var ids []string
		for _, c := range got {
			ids = append(ids, c.ClientID)
		}
		mustEqual(t, ids, []string{"aa", "mm", "zz"})
	})
}
