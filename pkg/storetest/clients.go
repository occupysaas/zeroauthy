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
		TenantID:        tenantID,
		IsFirstParty:    true,
		ClientID:        clientID,
		Name:            "App " + clientID,
		AppType:         store.AppTypeNonInteractive,
		IDTokenLifetime: 600,
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
		want.Origin = store.OriginAPI
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

	t.Run("DeleteCascades", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_a", "gone")))
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_a", "kept")))
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_b", "gone")))
		for _, tn := range []string{"ten_a", "ten_b"} {
			mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant(tn, "cg_gone", "gone", "https://api.test")))
			_, err := s.UserGrants().Upsert(ctx, newUserGrant(tn, "ug_gone", "gone", "auth0|u1", "https://api.test", "read"))
			mustNoErr(t, err)
			rt := newRefreshToken(tn, "rt_gone", "h_gone", "f_gone")
			rt.ClientID = "gone"
			mustNoErr(t, s.RefreshTokens().Create(ctx, rt))
		}
		mustNoErr(t, s.ClientGrants().Create(ctx, newClientGrant("ten_a", "cg_kept", "kept", "https://api.test")))
		_, err := s.UserGrants().Upsert(ctx, newUserGrant("ten_a", "ug_kept", "kept", "auth0|u1", "https://api.test", "read"))
		mustNoErr(t, err)
		rt := newRefreshToken("ten_a", "rt_kept", "h_kept", "f_kept")
		rt.ClientID = "kept"
		mustNoErr(t, s.RefreshTokens().Create(ctx, rt))

		mustNoErr(t, s.Clients().Delete(ctx, "ten_a", "gone"))

		_, err = s.ClientGrants().Find(ctx, "ten_a", "gone", "https://api.test", store.SubjectTypeClient)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.UserGrants().Find(ctx, "ten_a", "gone", "auth0|u1", "https://api.test")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h_gone")
		mustErrIs(t, err, store.ErrNotFound)
		// Other clients and the same client ID in another tenant keep theirs.
		_, err = s.ClientGrants().Find(ctx, "ten_a", "kept", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		_, err = s.UserGrants().Find(ctx, "ten_a", "kept", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_a", "h_kept")
		mustNoErr(t, err)
		_, err = s.ClientGrants().Find(ctx, "ten_b", "gone", "https://api.test", store.SubjectTypeClient)
		mustNoErr(t, err)
		_, err = s.UserGrants().Find(ctx, "ten_b", "gone", "auth0|u1", "https://api.test")
		mustNoErr(t, err)
		_, err = s.RefreshTokens().GetByTokenHash(ctx, "ten_b", "h_gone")
		mustNoErr(t, err)
	})

	t.Run("ThirdPartyFields", func(t *testing.T) {
		s := open(t, newStore)
		yes, no := true, false
		for i, skip := range []*bool{nil, &yes, &no} {
			c := newClient("ten_a", "tp"+string(rune('0'+i)))
			c.IsFirstParty = false
			c.ThirdPartySecurityMode = store.SecurityModePermissive
			c.RedirectionPolicy = store.RedirectionPolicyAllowAlways
			c.SkipNonVerifiableCallbackURIConfirmationPrompt = skip
			mustNoErr(t, s.Clients().Create(ctx, c))
			got, err := s.Clients().Get(ctx, "ten_a", c.ClientID)
			mustNoErr(t, err)
			mustEqual(t, got, c)
		}
		got, err := s.Clients().Get(ctx, "ten_a", "tp1")
		mustNoErr(t, err)
		*got.SkipNonVerifiableCallbackURIConfirmationPrompt = false // must not reach the store
		again, err := s.Clients().Get(ctx, "ten_a", "tp1")
		mustNoErr(t, err)
		mustEqual(t, *again.SkipNonVerifiableCallbackURIConfirmationPrompt, true)
	})

	t.Run("RequirePAR", func(t *testing.T) {
		s := open(t, newStore)
		c := newClient("ten_a", "par")
		c.RequirePushedAuthorizationRequests = true
		mustNoErr(t, s.Clients().Create(ctx, c))
		got, err := s.Clients().Get(ctx, "ten_a", "par")
		mustNoErr(t, err)
		mustEqual(t, got, c)

		c.RequirePushedAuthorizationRequests = false
		mustNoErr(t, s.Clients().Update(ctx, c))
		got, err = s.Clients().Get(ctx, "ten_a", "par")
		mustNoErr(t, err)
		mustEqual(t, got, c)
	})

	t.Run("SealedSecrets", func(t *testing.T) {
		s := open(t, newStore)
		exp := ts(72 * time.Hour)
		c := newClient("ten_a", "sealed")
		c.Secrets = []store.ClientSecret{
			{Sealed: []byte{0x00, 0xff, '{', '"', 0x80, 0x7f}, CreatedAt: ts(0)},
			{Hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA", CreatedAt: ts(time.Hour), ExpiresAt: &exp},
		}
		mustNoErr(t, s.Clients().Create(ctx, c))
		got, err := s.Clients().Get(ctx, "ten_a", "sealed")
		mustNoErr(t, err)
		mustEqual(t, got, c)

		// A returned blob is a copy.
		got.Secrets[0].Sealed[0] = 0x42
		again, err := s.Clients().Get(ctx, "ten_a", "sealed")
		mustNoErr(t, err)
		mustEqual(t, again.Secrets[0].Sealed, []byte{0x00, 0xff, '{', '"', 0x80, 0x7f})

		// Converting to the sealed form drops the hash.
		c.Secrets = []store.ClientSecret{{Sealed: []byte("sealed-v2"), CreatedAt: ts(2 * time.Hour)}}
		mustNoErr(t, s.Clients().Update(ctx, c))
		got, err = s.Clients().Get(ctx, "ten_a", "sealed")
		mustNoErr(t, err)
		mustEqual(t, got, c)
		mustEqual(t, got.Secrets[0].Hash, "")
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

	t.Run("ListOrderedByCreatedAtThenClientID", func(t *testing.T) {
		s := open(t, newStore)
		for _, c := range []struct {
			id      string
			created time.Duration
		}{{"zz", 0}, {"aa", time.Hour}, {"mm", 0}, {"bb", time.Hour}, {"yy", -time.Hour}} {
			x := newClient("ten_a", c.id)
			x.CreatedAt = ts(c.created)
			mustNoErr(t, s.Clients().Create(ctx, x))
		}
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_b", "other")))
		got, total, err := s.Clients().List(ctx, "ten_a", store.ClientFilter{}, store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 5)
		mustEqual(t, clientIDs(got), []string{"yy", "mm", "zz", "aa", "bb"})
	})

	t.Run("ListFilterAndPage", func(t *testing.T) {
		s := open(t, newStore)
		yes, no := true, false
		for i, c := range []struct {
			id    string
			typ   store.AppType
			first bool
		}{
			{"c1", store.AppTypeSPA, true},
			{"c2", store.AppTypeNative, false},
			{"c3", store.AppTypeRegularWeb, true},
			{"c4", store.AppTypeSPA, false},
			{"c5", store.AppTypeNonInteractive, true},
			{"c6", store.AppTypeSPA, true},
		} {
			x := newClient("ten_a", c.id)
			x.AppType, x.IsFirstParty, x.CreatedAt = c.typ, c.first, ts(time.Duration(i)*time.Minute)
			mustNoErr(t, s.Clients().Create(ctx, x))
		}
		other := newClient("ten_b", "c7")
		other.AppType = store.AppTypeSPA
		mustNoErr(t, s.Clients().Create(ctx, other))
		check := func(name string, f store.ClientFilter, p store.Page, wantIDs []string, wantTotal int) {
			t.Helper()
			got, total, err := s.Clients().List(ctx, "ten_a", f, p)
			mustNoErr(t, err)
			if len(wantIDs) == 0 {
				mustEqual(t, len(got), 0)
			} else {
				mustEqual(t, clientIDs(got), wantIDs)
			}
			mustEqual(t, total, wantTotal)
		}
		spa, native := string(store.AppTypeSPA), string(store.AppTypeNative)
		check("Type", store.ClientFilter{AppTypes: []string{spa}}, store.Page{}, []string{"c1", "c4", "c6"}, 3)
		check("Types", store.ClientFilter{AppTypes: []string{spa, native}}, store.Page{}, []string{"c1", "c2", "c4", "c6"}, 4)
		check("Unknown type", store.ClientFilter{AppTypes: []string{"nope"}}, store.Page{}, nil, 0)
		check("First party", store.ClientFilter{IsFirstParty: &yes}, store.Page{}, []string{"c1", "c3", "c5", "c6"}, 4)
		check("Third party", store.ClientFilter{IsFirstParty: &no}, store.Page{}, []string{"c2", "c4"}, 2)
		check("Both", store.ClientFilter{AppTypes: []string{spa}, IsFirstParty: &yes}, store.Page{}, []string{"c1", "c6"}, 2)
		check("Page", store.ClientFilter{}, store.Page{Offset: 2, Limit: 2}, []string{"c3", "c4"}, 6)
		check("Last page", store.ClientFilter{}, store.Page{Offset: 5, Limit: 2}, []string{"c6"}, 6)
		check("Past the end", store.ClientFilter{}, store.Page{Offset: 9, Limit: 2}, nil, 6)
		check("Filter and page", store.ClientFilter{AppTypes: []string{spa}}, store.Page{Offset: 1, Limit: 1}, []string{"c4"}, 3)
		check("Offset only", store.ClientFilter{}, store.Page{Offset: 4}, []string{"c5", "c6"}, 6)
	})
}

func clientIDs(cs []*store.Client) []string {
	var ids []string
	for _, c := range cs {
		ids = append(ids, c.ClientID)
	}
	return ids
}
