package storetest

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const fedTenant = "ten_fed"

// fedFixture creates a tenant with a database, a Google, an OAuth2 and an OIDC
// connection.
func fedFixture(t *testing.T, s store.Store) {
	t.Helper()
	ctx := context.Background()
	mustNoErr(t, s.Tenants().Create(ctx, newTenant("fed")))
	mustNoErr(t, s.Connections().Create(ctx, newConnection(fedTenant, "con_db", "Database")))
	for _, c := range []struct{ id, name, strategy string }{
		{"con_g", "google", "google-oauth2"}, {"con_o", "prov", "oauth2"}, {"con_i", "corp", "oidc"},
	} {
		mustNoErr(t, s.Connections().Create(ctx, &store.Connection{
			TenantID: fedTenant, ID: c.id, Name: c.name, Strategy: c.strategy, CreatedAt: ts(0),
			FederationRevision: 1, FederationSecretsSealed: []byte("sealed-" + c.id),
		}))
	}
}

func fedUser(userID, email string, ids ...store.Identity) *store.User {
	return &store.User{TenantID: fedTenant, UserID: userID, Email: email, Identities: ids, CreatedAt: ts(0), UpdatedAt: ts(0)}
}

func googleID(sub string) store.Identity {
	return store.Identity{Connection: "google", Provider: "google-oauth2", UserID: sub}
}

func oauthID(sub string) store.Identity {
	return store.Identity{Connection: "prov", Provider: "oauth2", UserID: "prov|" + sub}
}

func fedKey(conn, sub string) store.FederatedIdentityKey {
	return store.FederatedIdentityKey{TenantID: fedTenant, ConnectionID: conn, Subject: sub}
}

func newAttempt(state, txID string, expires time.Time) *store.FederationAttempt {
	return &store.FederationAttempt{
		StateHash: state, TenantID: fedTenant, TransactionID: txID, ConnectionID: "con_g",
		Revision: 1, IdentityEpoch: 0, CookieHash: "cookie", Origin: "https://fed.example.test",
		CallbackURL: "https://fed.example.test/login/callback", Issuer: "https://accounts.google.com",
		Endpoints:   store.FederationEndpoints{AuthorizationURL: "https://a.test/auth", TokenURL: "https://a.test/token", JWKSURL: "https://a.test/jwks", UserInfoURL: "https://a.test/userinfo", TokenAuthMethod: "client_secret_post"},
		SealedProof: []byte("proof-" + state), ExpiresAt: expires, Status: store.AttemptPending, CreatedAt: ts(0),
	}
}

func testFederation(t *testing.T, newStore Factory) {
	ctx := context.Background()
	exp := ts(5 * time.Minute)

	t.Run("MicrosoftIdentityIndex", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		const tid = "11111111-2222-3333-4444-555555555555"
		for _, c := range []*store.Connection{
			{TenantID: fedTenant, ID: "ms", Name: "personal", Strategy: "windowslive"},
			{TenantID: fedTenant, ID: "work", Name: "work", Strategy: "waad", Extra: map[string]any{"useCommonEndpoint": true}},
		} {
			mustNoErr(t, s.Connections().Create(ctx, c))
		}
		for _, tc := range []struct{ provider, conn, name, sub, id string }{
			{"windowslive", "ms", "personal", "Case|Sensitive", "Case|Sensitive"},
			{"windowslive", "ms", "personal", "case|Sensitive", "case|Sensitive"},
			{"waad", "work", "work", tid + ":" + oid, "work|" + tid + ":" + oid},
			{"waad", "work", "work", "22222222-2222-3333-4444-555555555555:" + oid, "work|22222222-2222-3333-4444-555555555555:" + oid},
		} {
			owner := store.FederatedPublicID(tc.provider, tc.name, tc.sub)
			u := fedUser(owner, "same@example.test", store.Identity{Connection: tc.name, Provider: tc.provider, UserID: tc.id})
			mustNoErr(t, s.Users().Create(ctx, u))
			u.Identities[0].UserID = "modified"
			got, err := s.Users().FindByIdentity(ctx, fedTenant, tc.conn, tc.sub)
			mustNoErr(t, err)
			if got.UserID != owner || got.Identities[0].UserID != tc.id {
				t.Fatalf("round trip %+v", got)
			}
			got.Identities[0].UserID = "modified"
			got, err = s.Users().FindByIdentity(ctx, fedTenant, tc.conn, tc.sub)
			mustNoErr(t, err)
			if got.Identities[0].UserID != tc.id {
				t.Fatal("identity alias")
			}
			mustErrIs(t, s.Users().Create(ctx, fedUser("thief|"+owner, "", store.Identity{Connection: tc.name, Provider: tc.provider, UserID: tc.id})), store.ErrConflict)
			key := fedKey(tc.conn, tc.sub)
			mustNoErr(t, s.Federation().PutTokens(ctx, key, []byte("sealed")))
			// Failed transfer leaves ownership and tokens untouched.
			rollback := errors.New("rollback")
			err = s.WithTx(ctx, func(tx store.Store) error {
				got.Identities = nil
				if e := tx.Users().Update(ctx, got); e != nil {
					return e
				}
				if e := tx.Users().Create(ctx, fedUser("moved|"+owner, "", store.Identity{Connection: tc.name, Provider: tc.provider, UserID: tc.id})); e != nil {
					return e
				}
				return rollback
			})
			mustErrIs(t, err, rollback)
			got, err = s.Users().FindByIdentity(ctx, fedTenant, tc.conn, tc.sub)
			mustNoErr(t, err)
			if got.UserID != owner {
				t.Fatal("rollback ownership")
			}
			mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
				got.Identities = nil
				if e := tx.Users().Update(ctx, got); e != nil {
					return e
				}
				return tx.Users().Create(ctx, fedUser("moved|"+owner, "", store.Identity{Connection: tc.name, Provider: tc.provider, UserID: tc.id}))
			}))
			got, err = s.Users().FindByIdentity(ctx, fedTenant, tc.conn, tc.sub)
			mustNoErr(t, err)
			if got.UserID != "moved|"+owner {
				t.Fatal("transfer owner")
			}
			tok, err := s.Federation().GetTokens(ctx, key)
			mustNoErr(t, err)
			if string(tok) != "sealed" {
				t.Fatal("transfer lost tokens")
			}
			mustNoErr(t, s.Users().Delete(ctx, fedTenant, got.UserID))
			_, err = s.Federation().GetTokens(ctx, key)
			mustErrIs(t, err, store.ErrNotFound)
		}
		var wg sync.WaitGroup
		outcomes := make(chan error, 6)
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outcomes <- s.Users().Create(ctx, fedUser("windowslive|race", "same@example.test", store.Identity{Connection: "personal", Provider: "windowslive", UserID: "race"}))
			}()
		}
		wg.Wait()
		close(outcomes)
		winners := 0
		for err := range outcomes {
			if err == nil {
				winners++
			} else {
				mustErrIs(t, err, store.ErrConflict)
			}
		}
		if winners != 1 {
			t.Fatalf("%d concurrent owners", winners)
		}
	})

	t.Run("Attempts", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		f := s.Federation()
		a := newAttempt("s1", "tx1", exp)
		mustNoErr(t, f.CreateAttempt(ctx, a))
		mustErrIs(t, f.CreateAttempt(ctx, newAttempt("s1", "tx9", exp)), store.ErrConflict)
		a.SealedProof[0] = 'X'
		got, err := f.GetAttempt(ctx, fedTenant, "s1")
		mustNoErr(t, err)
		mustEqual(t, got, newAttempt("s1", "tx1", exp))
		got.SealedProof[0] = 'Y'
		again, _ := f.GetAttempt(ctx, fedTenant, "s1")
		if !bytes.Equal(again.SealedProof, []byte("proof-s1")) {
			t.Fatal("GetAttempt shares SealedProof")
		}
		_, err = f.GetAttempt(ctx, "ten_other", "s1")
		mustErrIs(t, err, store.ErrNotFound)

		_, err = f.ClaimAttempt(ctx, fedTenant, "s1", "wrong", "https://fed.example.test", ts(0))
		mustErrIs(t, err, store.ErrInvalid)
		_, err = f.ClaimAttempt(ctx, fedTenant, "s1", "cookie", "https://other.example.test", ts(0))
		mustErrIs(t, err, store.ErrInvalid)
		_, err = f.ClaimAttempt(ctx, fedTenant, "s1", "cookie", "https://fed.example.test", exp)
		mustErrIs(t, err, store.ErrNotFound) // expiry is exclusive
		mustErrIs(t, f.FinishAttempt(ctx, fedTenant, "s1"), store.ErrAlreadyUsed)
		claimed, err := f.ClaimAttempt(ctx, fedTenant, "s1", "cookie", "https://fed.example.test", exp.Add(-time.Microsecond))
		mustNoErr(t, err)
		if claimed.Status != store.AttemptClaimed || claimed.TransactionID != "tx1" {
			t.Fatalf("claimed %#v", claimed)
		}
		_, err = f.ClaimAttempt(ctx, fedTenant, "s1", "cookie", "https://fed.example.test", ts(0))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustNoErr(t, f.FinishAttempt(ctx, fedTenant, "s1"))
		mustErrIs(t, f.FinishAttempt(ctx, fedTenant, "s1"), store.ErrAlreadyUsed)
		mustErrIs(t, f.FinishAttempt(ctx, fedTenant, "missing"), store.ErrNotFound)
		_, err = f.ClaimAttempt(ctx, fedTenant, "missing", "cookie", "https://fed.example.test", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("Superseded", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		f := s.Federation()
		mustNoErr(t, f.CreateAttempt(ctx, newAttempt("old", "tx", exp)))
		mustNoErr(t, f.CreateAttempt(ctx, newAttempt("claimed-old", "tx2", exp)))
		_, err := f.ClaimAttempt(ctx, fedTenant, "claimed-old", "cookie", "https://fed.example.test", ts(0))
		mustNoErr(t, err)
		mustNoErr(t, f.CreateAttempt(ctx, newAttempt("new", "tx", exp)))
		mustNoErr(t, f.CreateAttempt(ctx, newAttempt("new2", "tx2", exp)))
		_, err = f.ClaimAttempt(ctx, fedTenant, "old", "cookie", "https://fed.example.test", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, f.FinishAttempt(ctx, fedTenant, "claimed-old"), store.ErrAlreadyUsed)
		old, err := f.GetAttempt(ctx, fedTenant, "old")
		mustNoErr(t, err)
		if !old.Superseded {
			t.Fatal("old attempt not marked superseded")
		}
		_, err = f.ClaimAttempt(ctx, fedTenant, "new", "cookie", "https://fed.example.test", ts(0))
		mustNoErr(t, err)
		// Independent tabs (transactions) do not supersede each other.
		cur, _ := f.GetAttempt(ctx, fedTenant, "new2")
		if cur.Superseded {
			t.Fatal("other transaction superseded")
		}
	})

	t.Run("ConcurrentClaim", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		mustNoErr(t, s.Federation().CreateAttempt(ctx, newAttempt("race", "tx", exp)))
		errs := parallel(8, func(int) error {
			_, err := s.Federation().ClaimAttempt(ctx, fedTenant, "race", "cookie", "https://fed.example.test", ts(0))
			return err
		})
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, store.ErrAlreadyUsed):
				t.Fatalf("claim error %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d winners", won)
		}
	})

	t.Run("RollbackAndSweep", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			mustNoErr(t, tx.Federation().CreateAttempt(ctx, newAttempt("rb", "tx", exp)))
			mustNoErr(t, tx.Federation().PutTokens(ctx, fedKey("con_g", "x"), []byte("sealed")))
			mustNoErr(t, tx.Federation().BumpIdentityEpoch(ctx, fedTenant))
			return boom
		})
		mustErrIs(t, err, boom)
		_, err = s.Federation().GetAttempt(ctx, fedTenant, "rb")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Federation().GetTokens(ctx, fedKey("con_g", "x"))
		mustErrIs(t, err, store.ErrNotFound)
		epoch, err := s.Federation().IdentityEpoch(ctx, fedTenant)
		mustNoErr(t, err)
		mustEqual(t, epoch, int64(0))

		mustNoErr(t, s.Federation().CreateAttempt(ctx, newAttempt("e1", "tx1", ts(time.Minute))))
		mustNoErr(t, s.Federation().CreateAttempt(ctx, newAttempt("e2", "tx2", ts(2*time.Minute))))
		mustNoErr(t, s.Federation().CreateAttempt(ctx, newAttempt("e3", "tx3", ts(3*time.Minute))))
		n, err := s.Federation().DeleteExpired(ctx, ts(2*time.Minute))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.Federation().GetAttempt(ctx, fedTenant, "e1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Federation().GetAttempt(ctx, fedTenant, "e2")
		mustNoErr(t, err)
	})

	t.Run("Epoch", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		f := s.Federation()
		_, err := f.IdentityEpoch(ctx, "ten_missing")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, f.BumpIdentityEpoch(ctx, "ten_missing"), store.ErrNotFound)
		mustNoErr(t, f.BumpIdentityEpoch(ctx, fedTenant))
		tn, err := s.Tenants().Get(ctx, fedTenant)
		mustNoErr(t, err)
		mustEqual(t, tn.IdentityEpoch, int64(1))
		tn.IdentityEpoch = 0
		tn.FriendlyName = "Renamed"
		mustNoErr(t, s.Tenants().Update(ctx, tn))
		epoch, _ := f.IdentityEpoch(ctx, fedTenant)
		mustEqual(t, epoch, int64(1)) // Tenants.Update never moves the epoch

		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|plain", "p@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "plain"})))
		mustNoErr(t, s.Users().Delete(ctx, fedTenant, "auth0|plain"))
		epoch, _ = f.IdentityEpoch(ctx, fedTenant)
		mustEqual(t, epoch, int64(2)) // every user deletion
		boom := errors.New("boom")
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|kept", "k@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "kept"})))
		mustErrIs(t, s.WithTx(ctx, func(tx store.Store) error {
			mustNoErr(t, tx.Users().Delete(ctx, fedTenant, "auth0|kept"))
			return boom
		}), boom)
		epoch, _ = f.IdentityEpoch(ctx, fedTenant)
		mustEqual(t, epoch, int64(2)) // failed deletion rolls the bump back
	})

	t.Run("IdentityIndex", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		u := fedUser("google-oauth2|Sub", "same@example.test", googleID("Sub"))
		mustNoErr(t, s.Users().Create(ctx, u))
		got, err := s.Users().FindByIdentity(ctx, fedTenant, "con_g", "Sub")
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "google-oauth2|Sub")
		_, err = s.Users().FindByIdentity(ctx, fedTenant, "con_g", "sub")
		mustErrIs(t, err, store.ErrNotFound) // case-sensitive
		_, err = s.Users().FindByIdentity(ctx, fedTenant, "con_o", "Sub")
		mustErrIs(t, err, store.ErrNotFound)

		// Same email, different subjects: distinct accounts, no login-key clash.
		mustNoErr(t, s.Users().Create(ctx, fedUser("google-oauth2|Other", "same@example.test", googleID("Other"))))
		if _, err := s.Users().FindByLogin(ctx, fedTenant, "google", "same@example.test"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("federated email indexed as a login: %v", err)
		}
		// A database user may share the email on its own connection.
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|db", "same@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "db"})))

		// A second owner of the same identity conflicts, even linked.
		mustErrIs(t, s.Users().Create(ctx, fedUser("auth0|thief", "t@example.test",
			store.Identity{Connection: "Database", Provider: "auth0", UserID: "thief"},
			store.Identity{Connection: "google", Provider: "google-oauth2", UserID: "Sub", ProfileData: map[string]any{"email": "x"}})), store.ErrConflict)

		// Delimiters belong to the subject after the fixed prefix.
		mustNoErr(t, s.Users().Create(ctx, fedUser("oauth2|prov|a|b", "", oauthID("a|b"))))
		got, err = s.Users().FindByIdentity(ctx, fedTenant, "con_o", "a|b")
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "oauth2|prov|a|b")

		for name, bad := range map[string]*store.User{
			"unknown connection": fedUser("google-oauth2|x", "", store.Identity{Connection: "nope", Provider: "google-oauth2", UserID: "x"}),
			"provider mismatch":  fedUser("oidc|google|x", "", store.Identity{Connection: "google", Provider: "oidc", UserID: "google|x"}),
			"missing prefix":     fedUser("oauth2|prov|y", "", store.Identity{Connection: "prov", Provider: "oauth2", UserID: "y"}),
			"empty subject":      fedUser("google-oauth2|", "", googleID("")),
		} {
			if err := s.Users().Create(ctx, bad); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("%s: %v", name, err)
			}
		}

		// Long subjects round-trip byte for byte at the 1024-byte limit.
		long := strings.Repeat("é", 512)
		mustNoErr(t, s.Users().Create(ctx, fedUser("oidc|corp|"+long, "", store.Identity{Connection: "corp", Provider: "oidc", UserID: "corp|" + long})))
		got, err = s.Users().FindByIdentity(ctx, fedTenant, "con_i", long)
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "oidc|corp|"+long)
		mustErrIs(t, s.Users().Create(ctx, fedUser("oidc|corp|"+long+"x", "", store.Identity{Connection: "corp", Provider: "oidc", UserID: "corp|" + long + "x"})), store.ErrInvalid)
	})

	t.Run("OwnerTransfer", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		mustNoErr(t, s.Users().Create(ctx, fedUser("google-oauth2|S", "a@example.test", googleID("S"))))
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|p", "p@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "p"})))
		mustNoErr(t, s.Federation().PutTokens(ctx, fedKey("con_g", "S"), []byte("tokens")))
		// Link: the secondary gives the identity up, the primary takes it,
		// then the empty secondary is deleted, all in one transaction.
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			sec, err := tx.Users().Get(ctx, fedTenant, "google-oauth2|S")
			if err != nil {
				return err
			}
			moved := sec.Identities[0]
			moved.ProfileData = map[string]any{"email": "a@example.test"}
			sec.Identities = nil
			if err := tx.Users().Update(ctx, sec); err != nil {
				return err
			}
			p, err := tx.Users().Get(ctx, fedTenant, "auth0|p")
			if err != nil {
				return err
			}
			p.Identities = append(p.Identities, moved)
			if err := tx.Users().Update(ctx, p); err != nil {
				return err
			}
			return tx.Users().Delete(ctx, fedTenant, "google-oauth2|S")
		}))
		got, err := s.Users().FindByIdentity(ctx, fedTenant, "con_g", "S")
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "auth0|p")
		tok, err := s.Federation().GetTokens(ctx, fedKey("con_g", "S"))
		mustNoErr(t, err)
		mustEqual(t, tok, []byte("tokens")) // tokens follow the identity, not the user
		epoch, _ := s.Federation().IdentityEpoch(ctx, fedTenant)
		if epoch < 1 {
			t.Fatalf("transfer did not bump epoch: %d", epoch)
		}

		// Updating without giving it up first conflicts.
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|q", "q@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "q"})))
		q, _ := s.Users().Get(ctx, fedTenant, "auth0|q")
		q.Identities = append(q.Identities, store.Identity{Connection: "google", Provider: "google-oauth2", UserID: "S", ProfileData: map[string]any{}})
		mustErrIs(t, s.Users().Update(ctx, q), store.ErrConflict)

		// Deleting the owner removes the index entry and the tokens.
		mustNoErr(t, s.Users().Delete(ctx, fedTenant, "auth0|p"))
		_, err = s.Users().FindByIdentity(ctx, fedTenant, "con_g", "S")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Federation().GetTokens(ctx, fedKey("con_g", "S"))
		mustErrIs(t, err, store.ErrNotFound)
		// A fresh login may provision the subject again.
		mustNoErr(t, s.Users().Create(ctx, fedUser("google-oauth2|S", "a@example.test", googleID("S"))))
	})

	t.Run("IndexPrimitives", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		f := s.Federation()
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|a", "a@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "a"})))
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|b", "b@example.test", store.Identity{Connection: "Database", Provider: "auth0", UserID: "b"})))
		k := fedKey("con_o", "subj")
		mustNoErr(t, f.PutIdentity(ctx, k, "auth0|a"))
		mustNoErr(t, f.PutIdentity(ctx, k, "auth0|a"))
		mustErrIs(t, f.PutIdentity(ctx, k, "auth0|b"), store.ErrConflict)
		mustErrIs(t, f.DeleteIdentity(ctx, k, "auth0|b"), store.ErrConflict)
		mustErrIs(t, f.DeleteIdentity(ctx, fedKey("con_o", "none"), "auth0|a"), store.ErrNotFound)
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Federation().DeleteIdentity(ctx, k, "auth0|a"); err != nil {
				return err
			}
			return tx.Federation().PutIdentity(ctx, k, "auth0|b")
		}))
		got, err := s.Users().FindByIdentity(ctx, fedTenant, "con_o", "subj")
		mustNoErr(t, err)
		mustEqual(t, got.UserID, "auth0|b")
		epoch, _ := f.IdentityEpoch(ctx, fedTenant)
		if epoch < 1 {
			t.Fatal("DeleteIdentity did not bump the epoch")
		}
	})

	t.Run("Tokens", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("fed2")))
		f := s.Federation()
		k1, k2 := fedKey("con_g", "a"), fedKey("con_g", "b")
		other := store.FederatedIdentityKey{TenantID: "ten_fed2", ConnectionID: "con_g", Subject: "a"}
		in := []byte("cipher-a")
		mustNoErr(t, f.PutTokens(ctx, k1, in))
		in[0] = 'X'
		mustNoErr(t, f.PutTokens(ctx, k2, []byte("cipher-b")))
		got, err := f.GetTokens(ctx, k1)
		mustNoErr(t, err)
		mustEqual(t, got, []byte("cipher-a"))
		got[0] = 'Y'
		again, _ := f.GetTokens(ctx, k1)
		mustEqual(t, again, []byte("cipher-a"))
		_, err = f.GetTokens(ctx, other)
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, f.PutTokens(ctx, k1, []byte("cipher-a2")))
		got, _ = f.GetTokens(ctx, k1)
		mustEqual(t, got, []byte("cipher-a2"))
		mustNoErr(t, f.DeleteTokens(ctx, k1))
		mustNoErr(t, f.DeleteTokens(ctx, k1))
		_, err = f.GetTokens(ctx, k1)
		mustErrIs(t, err, store.ErrNotFound)
		got, _ = f.GetTokens(ctx, k2)
		mustEqual(t, got, []byte("cipher-b"))
	})

	t.Run("ConnectionAndTenantDelete", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		mustNoErr(t, s.Users().Create(ctx, fedUser("google-oauth2|G", "g@example.test", googleID("G"))))
		mustNoErr(t, s.Users().Create(ctx, fedUser("auth0|p", "p@example.test",
			store.Identity{Connection: "Database", Provider: "auth0", UserID: "p"},
			store.Identity{Connection: "prov", Provider: "oauth2", UserID: "prov|L", ProfileData: map[string]any{"email": "l@example.test"}})))
		mustNoErr(t, s.Federation().PutTokens(ctx, fedKey("con_g", "G"), []byte("t1")))
		mustNoErr(t, s.Federation().PutTokens(ctx, fedKey("con_o", "L"), []byte("t2")))
		mustNoErr(t, s.Connections().Delete(ctx, fedTenant, "con_g"))
		mustNoErr(t, s.Connections().Delete(ctx, fedTenant, "con_o"))
		for _, k := range []store.FederatedIdentityKey{fedKey("con_g", "G"), fedKey("con_o", "L")} {
			_, err := s.Users().FindByIdentity(ctx, fedTenant, k.ConnectionID, k.Subject)
			mustErrIs(t, err, store.ErrNotFound)
			_, err = s.Federation().GetTokens(ctx, k)
			mustErrIs(t, err, store.ErrNotFound)
		}
		p, err := s.Users().Get(ctx, fedTenant, "auth0|p")
		mustNoErr(t, err)
		mustEqual(t, len(p.Identities), 1)

		mustNoErr(t, s.Users().Create(ctx, fedUser("oidc|corp|I", "", store.Identity{Connection: "corp", Provider: "oidc", UserID: "corp|I"})))
		mustNoErr(t, s.Federation().PutTokens(ctx, fedKey("con_i", "I"), []byte("t3")))
		mustNoErr(t, s.Federation().CreateAttempt(ctx, newAttempt("st", "tx", exp)))
		mustNoErr(t, s.Tenants().Delete(ctx, fedTenant))
		_, err = s.Federation().GetTokens(ctx, fedKey("con_i", "I"))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Federation().GetAttempt(ctx, fedTenant, "st")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Users().FindByIdentity(ctx, fedTenant, "con_i", "I")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ConnectionColumns", func(t *testing.T) {
		s := open(t, newStore)
		fedFixture(t, s)
		c, err := s.Connections().Get(ctx, fedTenant, "con_g")
		mustNoErr(t, err)
		if c.FederationRevision != 1 || string(c.FederationSecretsSealed) != "sealed-con_g" {
			t.Fatalf("connection federation fields %d %q", c.FederationRevision, c.FederationSecretsSealed)
		}
		c.FederationRevision, c.FederationSecretsSealed = 2, []byte("rotated")
		mustNoErr(t, s.Connections().Update(ctx, c))
		c, _ = s.Connections().Get(ctx, fedTenant, "con_g")
		if c.FederationRevision != 2 || string(c.FederationSecretsSealed) != "rotated" {
			t.Fatalf("updated federation fields %d %q", c.FederationRevision, c.FederationSecretsSealed)
		}
	})
}
