package storetest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Origin must survive every consume, state mutation and refresh rotation. Empty
// persisted origins remain empty so upgraded stores retain canonical semantics.
func testOriginRoundTrip(t *testing.T, newStore Factory) {
	for _, origin := range []string{"", "https://login.customer.example", "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 56) + ".test"} {
		name := "canonical"
		if origin != "" {
			name = "custom"
			if len(origin) > 255 {
				name = "custom-long"
			}
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := open(t, newStore)
			tn := newTenant("acme")
			tn.CanonicalHost = "acme.example.test"
			mustNoErr(t, s.Tenants().Create(ctx, tn))
			tenant, err := s.Tenants().Get(ctx, tn.ID)
			mustNoErr(t, err)
			mustEqual(t, tenant.CanonicalHost, tn.CanonicalHost)
			sess := newSession(tn.ID, "session", "session-hash")
			sess.Origin = origin
			mustNoErr(t, s.Sessions().Create(ctx, sess))
			mustNoErr(t, s.Sessions().Touch(ctx, tn.ID, sess.ID, ts(time.Second), ts(time.Hour), "ip", "agent"))
			mustNoErr(t, s.Sessions().AddClient(ctx, tn.ID, sess.ID, "client2"))
			session, err := s.Sessions().Get(ctx, tn.ID, sess.ID)
			mustNoErr(t, err)
			mustEqual(t, session.Origin, origin)
			txn := newAuthTransaction(tn.ID, "transaction")
			txn.Origin = origin
			mustNoErr(t, s.AuthTransactions().Create(ctx, txn))
			mustNoErr(t, s.AuthTransactions().CompareAndSwapHosted(ctx, tn.ID, txn.ID, 0, store.HostedLoginState{Step: "password"}, ts(time.Second)))
			transaction, err := s.AuthTransactions().Get(ctx, tn.ID, txn.ID)
			mustNoErr(t, err)
			mustEqual(t, transaction.Origin, origin)
			code := newAuthCode(tn.ID, "code")
			code.Origin = origin
			mustNoErr(t, s.AuthCodes().Create(ctx, code))
			consumed, err := s.AuthCodes().Consume(ctx, tn.ID, code.CodeHash, ts(time.Second))
			mustNoErr(t, err)
			mustEqual(t, consumed.Origin, origin)
			consumed, err = s.AuthCodes().Consume(ctx, tn.ID, code.CodeHash, ts(2*time.Second))
			mustErrIs(t, err, store.ErrAlreadyUsed)
			mustEqual(t, consumed.Origin, origin)
			par := newPushedAuthRequest(tn.ID, "par")
			par.Origin = origin
			mustNoErr(t, s.PushedAuthRequests().Create(ctx, par))
			pushed, err := s.PushedAuthRequests().Consume(ctx, tn.ID, par.IDHash, ts(time.Second))
			mustNoErr(t, err)
			mustEqual(t, pushed.Origin, origin)
			device := newDeviceCode(tn.ID, "device", "user-code")
			device.Origin = origin
			mustNoErr(t, s.DeviceCodes().Create(ctx, device))
			decided, err := s.DeviceCodes().Decide(ctx, tn.ID, device.DeviceCodeHash, store.DeviceDecision{Status: store.DeviceCodeApproved, UserID: "user"})
			mustNoErr(t, err)
			mustEqual(t, decided.Origin, origin)
			polled, err := s.DeviceCodes().Poll(ctx, tn.ID, device.DeviceCodeHash, ts(time.Second))
			mustNoErr(t, err)
			mustEqual(t, polled.Code.Origin, origin)
			refresh := newRefreshToken(tn.ID, "refresh", "refresh-hash", "family")
			refresh.Origin = origin
			mustNoErr(t, s.RefreshTokens().Create(ctx, refresh))
			next := newRefreshToken(tn.ID, "next", "next-hash", "family")
			next.Origin = origin
			mustNoErr(t, s.RefreshTokens().Rotate(ctx, tn.ID, refresh.ID, next, ts(time.Second), 0))
			old, err := s.RefreshTokens().Get(ctx, tn.ID, refresh.ID)
			mustNoErr(t, err)
			mustEqual(t, old.Origin, origin)
			rotated, err := s.RefreshTokens().Get(ctx, tn.ID, next.ID)
			mustNoErr(t, err)
			mustEqual(t, rotated.Origin, origin)
			mustNoErr(t, s.RefreshTokens().Touch(ctx, tn.ID, next.ID, ts(time.Hour)))
			rotated, err = s.RefreshTokens().Get(ctx, tn.ID, next.ID)
			mustNoErr(t, err)
			mustEqual(t, rotated.Origin, origin)
			reset := newTicket(tn.ID, "reset", "reset-hash")
			reset.Origin = origin
			mustNoErr(t, s.PasswordResetTickets().Create(ctx, reset))
			resetRead, err := s.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, reset.TokenHash)
			mustNoErr(t, err)
			mustEqual(t, resetRead.Origin, origin)
			resetRead, err = s.PasswordResetTickets().Consume(ctx, tn.ID, reset.TokenHash, ts(time.Second))
			mustNoErr(t, err)
			mustEqual(t, resetRead.Origin, origin)
			verify := newVerificationTicket(tn.ID, "verify", "verify-hash")
			verify.Origin = origin
			mustNoErr(t, s.EmailVerificationTickets().Create(ctx, verify))
			verifyRead, err := s.EmailVerificationTickets().GetByTokenHash(ctx, tn.ID, verify.TokenHash)
			mustNoErr(t, err)
			mustEqual(t, verifyRead.Origin, origin)
			verifyRead, err = s.EmailVerificationTickets().Consume(ctx, tn.ID, verify.TokenHash, ts(time.Second))
			mustNoErr(t, err)
			mustEqual(t, verifyRead.Origin, origin)
		})
	}
}
