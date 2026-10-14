package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newAuthCode(tenantID, hash string) *store.AuthCode {
	return &store.AuthCode{
		TenantID: tenantID, CodeHash: hash, ClientID: "spa", RedirectURI: "https://app.test/cb",
		UserID: "auth0|u1", SessionID: "s1", Scopes: []string{"openid", "email"},
		Audience: "https://api.test", Nonce: "n", CodeChallenge: "ch", CodeChallengeMethod: "S256",
		AuthTime: ts(0), ExpiresAt: ts(time.Minute), CreatedAt: ts(0),
	}
}

func testAuthCodes(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("ConsumeOnce", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		mustErrIs(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")), store.ErrConflict)

		got, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(10*time.Second))
		mustNoErr(t, err)
		want := newAuthCode("ten_a", "h1")
		used := ts(10 * time.Second)
		want.UsedAt = &used
		mustEqual(t, got, want)

		again, err := s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(20*time.Second))
		mustErrIs(t, err, store.ErrAlreadyUsed)
		mustEqual(t, again.UsedAt.Equal(used), true) // the first use time is kept
		mustEqual(t, again.ClientID, "spa")
	})

	t.Run("UnknownAndOtherTenant", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.AuthCodes().Create(ctx, newAuthCode("ten_a", "h1")))
		_, err := s.AuthCodes().Consume(ctx, "ten_a", "nope", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.AuthCodes().Consume(ctx, "ten_b", "h1", ts(0))
		mustErrIs(t, err, store.ErrNotFound)
		// The failed cross-tenant attempt must not have consumed it.
		_, err = s.AuthCodes().Consume(ctx, "ten_a", "h1", ts(0))
		mustNoErr(t, err)
	})
}
