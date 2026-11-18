package storetest

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testClientCredentials runs the Plan 35 client credentials, assertion jti
// and token exchange profile storage contract. A driver that has not
// implemented it yet (UnimplementedClientCredentials) skips the suite.
func testClientCredentials(t *testing.T, newStore Factory) {
	ctx := context.Background()
	if !store.ClientCredentialsAvailable(ctx, open(t, newStore)) {
		t.Skip("driver has not implemented client credentials yet")
	}
	setup := func(t *testing.T) store.Store {
		s := open(t, newStore)
		for _, name := range []string{"a", "b"} {
			mustNoErr(t, s.Tenants().Create(ctx, newTenant(name)))
			mustNoErr(t, s.Clients().Create(ctx, newClient("ten_"+name, "web")))
		}
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_a", "other")))
		return s
	}
	cred := func(tid, client string, n int) *store.ClientCredential {
		return &store.ClientCredential{
			TenantID: tid, ClientID: client, ID: fmt.Sprintf("cred_%022d", n), Type: "public_key", Name: fmt.Sprintf("key %d", n),
			KID: fmt.Sprintf("kid-%016d", n), Alg: "RS256", PublicKeyDER: []byte{0x30, byte(n)}, Thumbprint: fmt.Sprintf("thumb-%d", n),
			CreatedAt: ts(time.Duration(n) * time.Second), UpdatedAt: ts(time.Duration(n) * time.Second),
		}
	}
	profile := func(tid string, n int) *store.TokenExchangeProfile {
		return &store.TokenExchangeProfile{
			TenantID: tid, ID: fmt.Sprintf("tep_%022d", n), Name: fmt.Sprintf("profile %d", n),
			SubjectTokenType: fmt.Sprintf("urn:example:type:%d", n), ActionID: "act_1", Type: "custom_authentication",
			CreatedAt: ts(0), UpdatedAt: ts(0),
		}
	}
	// The storage clock is the real one, so expiry cases use far past and
	// future instants.
	past, future := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), time.Now().Add(24*time.Hour).Truncate(time.Second)

	t.Run("CreateGetList", func(t *testing.T) {
		s := setup(t)
		exp := ts(time.Hour)
		c2, c1 := cred("ten_a", "web", 2), cred("ten_a", "web", 1)
		c1.ExpiresAt = &exp
		mustNoErr(t, s.ClientCredentials().Create(ctx, c2, 2))
		mustNoErr(t, s.ClientCredentials().Create(ctx, c1, 2))
		mustErrIs(t, s.ClientCredentials().Create(ctx, cred("ten_a", "web", 1), 5), store.ErrConflict)
		mustErrIs(t, s.ClientCredentials().Create(ctx, cred("ten_a", "ghost", 9), 2), store.ErrNotFound)
		got, err := s.ClientCredentials().Get(ctx, "ten_a", "web", c1.ID)
		mustNoErr(t, err)
		mustEqual(t, got, c1)
		list, err := s.ClientCredentials().List(ctx, "ten_a", "web")
		mustNoErr(t, err)
		mustEqual(t, list, []*store.ClientCredential{c1, c2})
		none, err := s.ClientCredentials().List(ctx, "ten_a", "other")
		mustNoErr(t, err)
		mustEqual(t, len(none), 0)
		mustNoErr(t, s.ClientCredentials().UpdateExpiry(ctx, "ten_a", "web", c2.ID, &exp))
		got, err = s.ClientCredentials().Get(ctx, "ten_a", "web", c2.ID)
		mustNoErr(t, err)
		mustEqual(t, got.ExpiresAt.Equal(exp), true)
		mustNoErr(t, s.ClientCredentials().UpdateExpiry(ctx, "ten_a", "web", c2.ID, nil))
		got, err = s.ClientCredentials().Get(ctx, "ten_a", "web", c2.ID)
		mustNoErr(t, err)
		mustEqual(t, got.ExpiresAt == nil, true)
	})

	t.Run("CredentialLimit", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.ClientCredentials().Create(ctx, cred("ten_a", "web", 1), 2))
		mustNoErr(t, s.ClientCredentials().Create(ctx, cred("ten_a", "web", 2), 2))
		mustErrIs(t, s.ClientCredentials().Create(ctx, cred("ten_a", "web", 3), 2), store.ErrPrecondition)
		mustNoErr(t, s.ClientCredentials().Create(ctx, cred("ten_a", "other", 4), 2)) // the limit is per client
	})

	t.Run("CredentialLimitConcurrent", func(t *testing.T) {
		s := setup(t)
		errs := parallel(6, func(i int) error { return s.ClientCredentials().Create(ctx, cred("ten_a", "web", i+1), 2) })
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			default:
				mustErrIs(t, err, store.ErrPrecondition)
			}
		}
		mustEqual(t, ok, 2)
	})

	t.Run("CredentialDeleteDetaches", func(t *testing.T) {
		s := setup(t)
		c1, c2 := cred("ten_a", "web", 1), cred("ten_a", "web", 2)
		mustNoErr(t, s.ClientCredentials().Create(ctx, c1, 2))
		mustNoErr(t, s.ClientCredentials().Create(ctx, c2, 2))
		cl, err := s.Clients().Get(ctx, "ten_a", "web")
		mustNoErr(t, err)
		cl.PrivateKeyJWTCredentials = []string{c1.ID, c2.ID}
		cl.SignedRequestObject = &store.SignedRequestObject{Required: true, Credentials: []string{c1.ID, c2.ID}}
		mustNoErr(t, s.Clients().Update(ctx, cl))
		mustNoErr(t, s.ClientCredentials().Delete(ctx, "ten_a", "web", c1.ID))
		_, err = s.ClientCredentials().Get(ctx, "ten_a", "web", c1.ID)
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.ClientCredentials().Delete(ctx, "ten_a", "web", c1.ID), store.ErrNotFound)
		cl, err = s.Clients().Get(ctx, "ten_a", "web")
		mustNoErr(t, err)
		mustEqual(t, cl.PrivateKeyJWTCredentials, []string{c2.ID})
		mustEqual(t, cl.SignedRequestObject, &store.SignedRequestObject{Required: true, Credentials: []string{c2.ID}})
	})

	t.Run("CredentialTenantScoped", func(t *testing.T) {
		s := setup(t)
		c := cred("ten_a", "web", 1)
		mustNoErr(t, s.ClientCredentials().Create(ctx, c, 2))
		_, err := s.ClientCredentials().Get(ctx, "ten_a", "other", c.ID)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.ClientCredentials().Get(ctx, "ten_b", "web", c.ID)
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.ClientCredentials().UpdateExpiry(ctx, "ten_a", "other", c.ID, nil), store.ErrNotFound)
		mustErrIs(t, s.ClientCredentials().Delete(ctx, "ten_a", "other", c.ID), store.ErrNotFound)
		_, err = s.ClientCredentials().Get(ctx, "ten_a", "web", c.ID) // the failed attempts changed nothing
		mustNoErr(t, err)
	})

	t.Run("ClientDeleteRemovesCredentials", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.ClientCredentials().Create(ctx, cred("ten_a", "web", 1), 2))
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j1", future))
		mustNoErr(t, s.Clients().Delete(ctx, "ten_a", "web"))
		mustNoErr(t, s.Clients().Create(ctx, newClient("ten_a", "web")))
		list, err := s.ClientCredentials().List(ctx, "ten_a", "web")
		mustNoErr(t, err)
		mustEqual(t, len(list), 0)
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j1", future))
	})

	t.Run("JTIOneWinner", func(t *testing.T) {
		s := setup(t)
		errs := parallel(8, func(int) error { return s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "same-jti", future) })
		won := 0
		for _, err := range errs {
			if err == nil {
				won++
				continue
			}
			mustErrIs(t, err, store.ErrConflict)
		}
		mustEqual(t, won, 1)
	})

	t.Run("JTIScope", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", future))
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "other", "j", future))
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_b", "web", "j", future))
		mustErrIs(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", future), store.ErrConflict)
	})

	t.Run("JTIReuseAfterExpiry", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", past)) // already expired
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", future))
		mustErrIs(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", future), store.ErrConflict)
	})

	t.Run("JTIPurge", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "old1", ts(0)))
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "old2", ts(time.Second)))
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "live", future))
		n, err := s.ClientCredentials().PurgeJTIs(ctx, ts(time.Minute), 1)
		mustNoErr(t, err)
		mustEqual(t, n, 1) // the limit bounds one batch
		n, err = s.ClientCredentials().PurgeJTIs(ctx, ts(time.Minute), 10)
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		n, err = s.ClientCredentials().PurgeJTIs(ctx, ts(time.Minute), 10)
		mustNoErr(t, err)
		mustEqual(t, n, 0)
		mustErrIs(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "live", future), store.ErrConflict) // unexpired row kept
	})

	t.Run("ProfileCRUD", func(t *testing.T) {
		s := setup(t)
		p := profile("ten_a", 1)
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, p, 100))
		mustErrIs(t, s.ClientCredentials().CreateProfile(ctx, p, 100), store.ErrConflict)
		got, err := s.ClientCredentials().GetProfile(ctx, "ten_a", p.ID)
		mustNoErr(t, err)
		mustEqual(t, got, p)
		byType, err := s.ClientCredentials().GetProfileByType(ctx, "ten_a", p.SubjectTokenType)
		mustNoErr(t, err)
		mustEqual(t, byType, p)
		_, err = s.ClientCredentials().GetProfile(ctx, "ten_b", p.ID)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.ClientCredentials().GetProfileByType(ctx, "ten_b", p.SubjectTokenType)
		mustErrIs(t, err, store.ErrNotFound)
		p.Name, p.SubjectTokenType, p.ActionID, p.UpdatedAt = "renamed", "urn:example:other", "act_2", ts(time.Minute)
		mustNoErr(t, s.ClientCredentials().UpdateProfile(ctx, p))
		got, err = s.ClientCredentials().GetProfile(ctx, "ten_a", p.ID)
		mustNoErr(t, err)
		mustEqual(t, got, p)
		missing := profile("ten_a", 9)
		mustErrIs(t, s.ClientCredentials().UpdateProfile(ctx, missing), store.ErrNotFound)
		mustNoErr(t, s.ClientCredentials().DeleteProfile(ctx, "ten_a", p.ID))
		mustErrIs(t, s.ClientCredentials().DeleteProfile(ctx, "ten_a", p.ID), store.ErrNotFound)
	})

	t.Run("ProfileUniqueType", func(t *testing.T) {
		s := setup(t)
		a, b := profile("ten_a", 1), profile("ten_a", 2)
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, a, 100))
		dup := profile("ten_a", 3)
		dup.SubjectTokenType = a.SubjectTokenType
		mustErrIs(t, s.ClientCredentials().CreateProfile(ctx, dup, 100), store.ErrConflict)
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_b", 1), 100)) // unique per tenant
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, b, 100))
		b.SubjectTokenType = a.SubjectTokenType
		mustErrIs(t, s.ClientCredentials().UpdateProfile(ctx, b), store.ErrConflict)
		mustNoErr(t, s.ClientCredentials().UpdateProfile(ctx, a)) // keeping its own type is not a conflict
	})

	t.Run("ProfileLimit", func(t *testing.T) {
		s := setup(t)
		for i := 1; i <= 100; i++ {
			mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_a", i), 100))
		}
		mustErrIs(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_a", 101), 100), store.ErrPrecondition)
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_b", 101), 100))
		mustNoErr(t, s.ClientCredentials().DeleteProfile(ctx, "ten_a", profile("ten_a", 1).ID))
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_a", 101), 100))
	})

	t.Run("ProfileCheckpoint", func(t *testing.T) {
		s := setup(t)
		for _, i := range []int{3, 1, 5, 2, 4} {
			mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_a", i), 100))
		}
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_b", 6), 100))
		var ids []string
		from := ""
		for range 10 {
			page, next, err := s.ClientCredentials().ListProfiles(ctx, "ten_a", from, 2)
			mustNoErr(t, err)
			for _, p := range page {
				ids = append(ids, p.ID)
			}
			if next == "" {
				break
			}
			mustEqual(t, next, page[len(page)-1].ID)
			from = next
		}
		want := make([]string, 0, 5)
		for i := 1; i <= 5; i++ {
			want = append(want, profile("ten_a", i).ID)
		}
		mustEqual(t, ids, want)
		empty, next, err := s.ClientCredentials().ListProfiles(ctx, "ten_a", want[4], 2)
		mustNoErr(t, err)
		mustEqual(t, len(empty), 0)
		mustEqual(t, next, "")
	})

	t.Run("ProfileCheckpointMixedCase", func(t *testing.T) {
		s := setup(t)
		// Byte order: uppercase sorts before lowercase, which locale
		// collations get wrong; the keyset cursor must agree with ORDER BY.
		want := []string{"tep_A0", "tep_B0", "tep_a0", "tep_b0"}
		for i, id := range []string{"tep_b0", "tep_A0", "tep_a0", "tep_B0"} {
			p := profile("ten_a", i+1)
			p.ID = id
			mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, p, 100))
		}
		var ids []string
		from := ""
		for range 10 {
			page, next, err := s.ClientCredentials().ListProfiles(ctx, "ten_a", from, 2)
			mustNoErr(t, err)
			for _, p := range page {
				ids = append(ids, p.ID)
			}
			if next == "" {
				break
			}
			from = next
		}
		mustEqual(t, ids, want)
	})

	t.Run("ProfilesForAction", func(t *testing.T) {
		s := setup(t)
		for i := 1; i <= 3; i++ {
			p := profile("ten_a", i)
			p.ActionID = []string{"act_1", "act_1", "act_2"}[i-1]
			mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, p, 100))
		}
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_b", 1), 100))
		for action, want := range map[string]int{"act_1": 2, "act_2": 1, "act_3": 0} {
			n, err := s.ClientCredentials().ProfilesForAction(ctx, "ten_a", action)
			mustNoErr(t, err)
			mustEqual(t, n, want)
		}
	})

	t.Run("TenantDeleteRemovesRows", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.ClientCredentials().Create(ctx, cred("ten_a", "web", 1), 2))
		mustNoErr(t, s.ClientCredentials().CreateProfile(ctx, profile("ten_a", 1), 100))
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", future))
		mustNoErr(t, s.Tenants().Delete(ctx, "ten_a"))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("a")))
		_, err := s.ClientCredentials().GetProfile(ctx, "ten_a", profile("ten_a", 1).ID)
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, s.ClientCredentials().UseJTI(ctx, "ten_a", "web", "j", future))
	})

	t.Run("ClientFieldsRoundTrip", func(t *testing.T) {
		s := setup(t)
		c := newClient("ten_a", "fields")
		c.PrivateKeyJWTCredentials = []string{"cred_a", "cred_b"}
		c.SignedRequestObject = &store.SignedRequestObject{Required: true, Credentials: []string{"cred_a"}}
		c.TokenExchangeTypes = []string{"urn:example:type:1", "https://example.test/t"}
		mustNoErr(t, s.Clients().Create(ctx, c))
		got, err := s.Clients().Get(ctx, "ten_a", "fields")
		mustNoErr(t, err)
		mustEqual(t, got, c)
		// Unset values stay unset.
		plain := newClient("ten_a", "plain")
		mustNoErr(t, s.Clients().Create(ctx, plain))
		got, err = s.Clients().Get(ctx, "ten_a", "plain")
		mustNoErr(t, err)
		mustEqual(t, got.PrivateKeyJWTCredentials == nil && got.SignedRequestObject == nil && got.TokenExchangeTypes == nil, true)
		c.PrivateKeyJWTCredentials, c.SignedRequestObject, c.TokenExchangeTypes = nil, nil, nil
		mustNoErr(t, s.Clients().Update(ctx, c))
		got, err = s.Clients().Get(ctx, "ten_a", "fields")
		mustNoErr(t, err)
		mustEqual(t, got, c)
	})

	t.Run("ResourceServerSigningSecret", func(t *testing.T) {
		s := setup(t)
		rs := newResourceServer("ten_a", "hs", "https://hs.test")
		rs.SigningAlg = "HS256"
		rs.SigningSecretSealed = []byte("sealed-secret")
		mustNoErr(t, s.ResourceServers().Create(ctx, rs))
		got, err := s.ResourceServers().Get(ctx, "ten_a", "hs")
		mustNoErr(t, err)
		mustEqual(t, got, rs)
		rs.SigningSecretSealed = []byte("rotated")
		mustNoErr(t, s.ResourceServers().Update(ctx, rs))
		got, err = s.ResourceServers().Get(ctx, "ten_a", "hs")
		mustNoErr(t, err)
		mustEqual(t, slices.Clone(got.SigningSecretSealed), []byte("rotated"))
	})

	t.Run("PushedAuthRequestSigned", func(t *testing.T) {
		s := setup(t)
		p := newPushedAuthRequest("ten_a", "signed")
		p.Signed = true
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, p))
		got, err := s.PushedAuthRequests().Get(ctx, "ten_a", "signed")
		mustNoErr(t, err)
		mustEqual(t, got, p)
		plain := newPushedAuthRequest("ten_a", "plain")
		mustNoErr(t, s.PushedAuthRequests().Create(ctx, plain))
		got, err = s.PushedAuthRequests().Get(ctx, "ten_a", "plain")
		mustNoErr(t, err)
		mustEqual(t, got.Signed, false)
	})
}
