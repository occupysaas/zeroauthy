package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Phone runs the phone and passwordless storage contract against a fresh
// driver for each case.
func Phone(t *testing.T, factory Factory) {
	ctx := context.Background()
	now := ts(0)
	setup := func(t *testing.T) store.Store {
		s := open(t, factory)
		for _, tid := range []string{"a", "b"} {
			tenant := newTenant(tid)
			tenant.ID = tid
			mustNoErr(t, s.Tenants().Create(ctx, tenant))
		}
		return s
	}
	provider := func(tid, id string) *store.PhoneProvider {
		return &store.PhoneProvider{TenantID: tid, ID: id, Name: "twilio", Configuration: json.RawMessage(`{"sid":"AC1"}`), SealedCredentials: []byte("sealed-1"), CreatedAt: now, UpdatedAt: now}
	}
	code := func(tid, kind, hash string, exp time.Duration) *store.PasswordlessCode {
		return &store.PasswordlessCode{TenantID: tid, ConnectionID: "conn", Identifier: "+14155550100", ClientID: "c", Kind: kind, CodeHash: hash, Request: json.RawMessage(`{"x":1}`), ExpiresAt: now.Add(exp), CreatedAt: now}
	}

	t.Run("ProviderOnePerTenant", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, provider("a", "p1")))
		mustErrIs(t, s.Phone().CreatePhoneProvider(ctx, provider("a", "p2")), store.ErrConflict)
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, provider("b", "p3")))
		mustErrIs(t, s.Phone().CreatePhoneProvider(ctx, provider("missing", "p4")), store.ErrNotFound)
		got, err := s.Phone().ListPhoneProviders(ctx, "a")
		mustNoErr(t, err)
		if len(got) != 1 || got[0].ID != "p1" {
			t.Fatalf("list = %+v", got)
		}
		mustNoErr(t, s.Phone().DeletePhoneProvider(ctx, "a", "p1"))
		mustErrIs(t, s.Phone().DeletePhoneProvider(ctx, "a", "p1"), store.ErrNotFound)
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, provider("a", "p5")))
	})
	t.Run("ProviderSecretsRoundTripSealed", func(t *testing.T) {
		s := setup(t)
		p := provider("a", "p1")
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, p))
		got, err := s.Phone().GetPhoneProvider(ctx, "a", "p1")
		mustNoErr(t, err)
		if string(got.SealedCredentials) != "sealed-1" || string(got.Configuration) != `{"sid":"AC1"}` || got.Name != "twilio" {
			t.Fatalf("provider = %+v", got)
		}
		got.SealedCredentials[0] = 'X'
		p.SealedCredentials[1] = 'Y'
		again, _ := s.Phone().GetPhoneProvider(ctx, "a", "p1")
		if string(again.SealedCredentials) != "sealed-1" {
			t.Fatalf("stored credentials alias caller bytes: %q", again.SealedCredentials)
		}
		again.SealedCredentials, again.Disabled, again.UpdatedAt = []byte("sealed-2"), true, now.Add(time.Minute)
		mustNoErr(t, s.Phone().UpdatePhoneProvider(ctx, again))
		upd, err := s.Phone().GetPhoneProvider(ctx, "a", "p1")
		mustNoErr(t, err)
		if string(upd.SealedCredentials) != "sealed-2" || !upd.Disabled {
			t.Fatalf("update lost: %+v", upd)
		}
		mustErrIs(t, s.Phone().UpdatePhoneProvider(ctx, provider("a", "nope")), store.ErrNotFound)
	})
	t.Run("TemplateCRUD", func(t *testing.T) {
		s := setup(t)
		tpl := &store.PhoneTemplate{TenantID: "a", ID: "t1", Type: "otp_verify", Content: json.RawMessage(`{"body":{"text":"hi"}}`), Customizable: true, CreatedAt: now, UpdatedAt: now}
		mustNoErr(t, s.Phone().PutPhoneTemplate(ctx, tpl))
		tpl.Content, tpl.Disabled = json.RawMessage(`{"body":{"text":"bye"}}`), true
		mustNoErr(t, s.Phone().PutPhoneTemplate(ctx, tpl))
		got, err := s.Phone().GetPhoneTemplate(ctx, "a", "t1")
		mustNoErr(t, err)
		if string(got.Content) != `{"body":{"text":"bye"}}` || !got.Disabled || !got.Customizable || got.Type != "otp_verify" {
			t.Fatalf("template = %+v", got)
		}
		mustErrIs(t, s.Phone().PutPhoneTemplate(ctx, &store.PhoneTemplate{TenantID: "a", ID: "t2", Type: "otp_verify", CreatedAt: now, UpdatedAt: now}), store.ErrConflict)
		mustNoErr(t, s.Phone().PutPhoneTemplate(ctx, &store.PhoneTemplate{TenantID: "a", ID: "t3", Type: "otp_enroll", CreatedAt: now, UpdatedAt: now}))
		list, err := s.Phone().ListPhoneTemplates(ctx, "a")
		mustNoErr(t, err)
		if len(list) != 2 {
			t.Fatalf("list = %+v", list)
		}
		mustNoErr(t, s.Phone().DeletePhoneTemplate(ctx, "a", "t1"))
		_, err = s.Phone().GetPhoneTemplate(ctx, "a", "t1")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Phone().DeletePhoneTemplate(ctx, "a", "t1"), store.ErrNotFound)
	})
	t.Run("CodeReplacedByNewStart", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "old", time.Minute)))
		_, err := s.Phone().FailPasswordlessCode(ctx, "a", "conn", "+14155550100", "code", now)
		mustNoErr(t, err)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "new", time.Minute)))
		got, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "new", 1, now)
		mustNoErr(t, err)
		if got.Attempts != 0 || got.ClientID != "c" || string(got.Request) != `{"x":1}` {
			t.Fatalf("replacement kept stale state: %+v", got)
		}
		_, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "new", 5, now)
		mustErrIs(t, err, store.ErrPrecondition)
		_, err = s.Phone().FailPasswordlessCode(ctx, "a", "conn", "+14155550100", "code", now)
		mustErrIs(t, err, store.ErrNotFound)
		// The replaced code is wrong for the new row and counts as an attempt.
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "old", time.Minute)))
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "new", time.Minute)))
		_, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "old", 5, now)
		mustErrIs(t, err, store.ErrPrecondition)
		got, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "new", 5, now)
		mustNoErr(t, err)
		if got.Attempts != 1 {
			t.Fatalf("wrong guess not counted: attempts = %d", got.Attempts)
		}
	})
	t.Run("CodeWrongGuessCounted", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		for range 2 {
			_, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "bad", 3, now)
			mustErrIs(t, err, store.ErrPrecondition)
		}
		got, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 3, now)
		mustNoErr(t, err)
		if got.Attempts != 2 {
			t.Fatalf("attempts = %d", got.Attempts)
		}
		// The third wrong guess exhausts a max of 3.
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		for range 3 {
			_, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "bad", 3, now)
			mustErrIs(t, err, store.ErrPrecondition)
		}
		_, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 3, now)
		mustErrIs(t, err, store.ErrPrecondition)
	})
	t.Run("CodeWrongGuessesConcurrent", func(t *testing.T) {
		s := setup(t)
		const max = 3
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		var wg sync.WaitGroup
		var won atomic.Pointer[store.PasswordlessCode]
		for i := range 21 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				hash := "bad"
				if i == 10 {
					hash = "h"
				}
				got, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", hash, max, now)
				if err == nil {
					won.Store(got)
				} else if !isErr(err, store.ErrPrecondition) {
					t.Errorf("consume: %v", err)
				}
			}()
		}
		wg.Wait()
		// Accepted guesses (counted wrong ones plus a success) never exceed max.
		if got := won.Load(); got != nil {
			if got.Attempts+1 > max {
				t.Fatalf("success after %d wrong guesses (max %d)", got.Attempts, max)
			}
			return
		}
		got, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 100, now)
		mustNoErr(t, err)
		if got.Attempts != max {
			t.Fatalf("attempts = %d, want exactly %d", got.Attempts, max)
		}
	})
	t.Run("CodeConsumeOnceConcurrent", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		var wg sync.WaitGroup
		var ok, pre, other atomic.Int32
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 5, now)
				switch {
				case err == nil:
					ok.Add(1)
				case isErr(err, store.ErrPrecondition):
					pre.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || pre.Load() != 19 || other.Load() != 0 {
			t.Fatalf("ok=%d precondition=%d other=%d", ok.Load(), pre.Load(), other.Load())
		}
	})
	t.Run("CodeAttemptLimit", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		for want := 1; want <= 3; want++ {
			n, err := s.Phone().FailPasswordlessCode(ctx, "a", "conn", "+14155550100", "code", now)
			mustNoErr(t, err)
			if n != want {
				t.Fatalf("attempts = %d, want %d", n, want)
			}
		}
		_, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 3, now)
		mustErrIs(t, err, store.ErrPrecondition)
		got, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 4, now)
		mustNoErr(t, err)
		if got.Attempts != 3 {
			t.Fatalf("attempts = %d", got.Attempts)
		}
	})
	t.Run("CodeExpired", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		_, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 5, now.Add(time.Minute))
		mustErrIs(t, err, store.ErrPrecondition)
		_, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 5, now.Add(time.Minute-time.Second))
		mustNoErr(t, err)
	})
	t.Run("LinkPeekDoesNotConsume", func(t *testing.T) {
		s := setup(t)
		l := code("a", "link", "lh", time.Minute)
		l.Identifier = "x@example.test"
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, l))
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "ch", time.Minute)))
		for range 2 {
			got, err := s.Phone().PeekPasswordlessLink(ctx, "a", "lh", now)
			mustNoErr(t, err)
			if got.Identifier != "x@example.test" || got.Kind != "link" {
				t.Fatalf("peek = %+v", got)
			}
		}
		_, err := s.Phone().PeekPasswordlessLink(ctx, "a", "ch", now)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Phone().PeekPasswordlessLink(ctx, "a", "lh", now.Add(time.Minute))
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "x@example.test", "link", "lh", 5, now)
		mustNoErr(t, err)
		_, err = s.Phone().PeekPasswordlessLink(ctx, "a", "lh", now)
		mustErrIs(t, err, store.ErrNotFound)
	})
	t.Run("FindUsersByPhoneUsesNormalized", func(t *testing.T) {
		s := setup(t)
		mk := func(tid, uid, conn, number, norm string) {
			mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: tid, UserID: uid, PhoneNumber: number, PhoneNormalized: norm,
				Identities: []store.Identity{{Connection: conn, Provider: "auth0", UserID: uid}}}))
		}
		mk("a", "u1", "conn", "+1 (415) 555-0100", "+14155550100")
		mk("a", "u2", "conn", "+14155550100", "+14155550100")
		mk("a", "u3", "other", "+14155550100", "+14155550100")
		mk("a", "u4", "conn", "4155550100", "")
		mk("b", "u5", "conn", "+14155550100", "+14155550100")
		got, err := s.Phone().FindUsersByPhone(ctx, "a", "conn", "+14155550100")
		mustNoErr(t, err)
		if len(got) != 2 || got[0].UserID != "u1" || got[1].UserID != "u2" || got[0].PhoneNumber != "+1 (415) 555-0100" {
			t.Fatalf("users = %+v", got)
		}
		none, err := s.Phone().FindUsersByPhone(ctx, "a", "conn", "")
		mustNoErr(t, err)
		if len(none) != 0 {
			t.Fatalf("empty number matched %+v", none)
		}
		none, err = s.Phone().FindUsersByPhone(ctx, "a", "conn", "4155550100")
		mustNoErr(t, err)
		if len(none) != 0 {
			t.Fatalf("raw number matched %+v", none)
		}
	})
	t.Run("PurgePhoneExpired", func(t *testing.T) {
		s := setup(t)
		for i, id := range []string{"1", "2", "3"} {
			c := code("a", "code", "h"+id, -time.Duration(i+1)*time.Second)
			c.Identifier = "+1415555010" + id
			mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, c))
		}
		live := code("a", "code", "live", time.Hour)
		live.Identifier = "+14155550199"
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, live))
		n, err := s.Phone().PurgePhone(ctx, now, 2)
		mustNoErr(t, err)
		if n != 2 {
			t.Fatalf("first purge = %d, want 2", n)
		}
		n, err = s.Phone().PurgePhone(ctx, now, 2)
		mustNoErr(t, err)
		if n != 1 {
			t.Fatalf("second purge = %d, want 1", n)
		}
		_, err = s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550199", "code", "live", 5, now)
		mustNoErr(t, err)
	})
	t.Run("DeleteTenantPhone", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, provider("a", "p1")))
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, provider("b", "p2")))
		mustNoErr(t, s.Phone().PutPhoneTemplate(ctx, &store.PhoneTemplate{TenantID: "a", ID: "t", Type: "otp_verify", CreatedAt: now, UpdatedAt: now}))
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, code("a", "code", "h", time.Minute)))
		mustNoErr(t, s.Phone().DeleteTenantPhone(ctx, "a"))
		if l, _ := s.Phone().ListPhoneProviders(ctx, "a"); len(l) != 0 {
			t.Fatalf("providers kept: %+v", l)
		}
		if l, _ := s.Phone().ListPhoneTemplates(ctx, "a"); len(l) != 0 {
			t.Fatalf("templates kept: %+v", l)
		}
		_, err := s.Phone().ConsumePasswordlessCode(ctx, "a", "conn", "+14155550100", "code", "h", 5, now)
		mustErrIs(t, err, store.ErrPrecondition)
		if l, _ := s.Phone().ListPhoneProviders(ctx, "b"); len(l) != 1 {
			t.Fatalf("other tenant affected: %+v", l)
		}
	})
	t.Run("TenantIsolation", func(t *testing.T) {
		s := setup(t)
		mustNoErr(t, s.Phone().CreatePhoneProvider(ctx, provider("a", "p1")))
		mustNoErr(t, s.Phone().PutPhoneTemplate(ctx, &store.PhoneTemplate{TenantID: "a", ID: "t", Type: "otp_verify", CreatedAt: now, UpdatedAt: now}))
		l := code("a", "link", "lh", time.Minute)
		mustNoErr(t, s.Phone().PutPasswordlessCode(ctx, l))
		mustNoErr(t, s.Users().Create(ctx, &store.User{TenantID: "a", UserID: "u", PhoneNormalized: "+14155550100", Identities: []store.Identity{{Connection: "conn", Provider: "auth0", UserID: "u"}}}))

		if _, err := s.Phone().GetPhoneProvider(ctx, "b", "p1"); !isErr(err, store.ErrNotFound) {
			t.Fatalf("GetPhoneProvider = %v", err)
		}
		if got, err := s.Phone().ListPhoneProviders(ctx, "b"); err != nil || len(got) != 0 {
			t.Fatalf("ListPhoneProviders = %v, %v", got, err)
		}
		mustErrIs(t, s.Phone().UpdatePhoneProvider(ctx, provider("b", "p1")), store.ErrNotFound)
		mustErrIs(t, s.Phone().DeletePhoneProvider(ctx, "b", "p1"), store.ErrNotFound)
		if _, err := s.Phone().GetPhoneTemplate(ctx, "b", "t"); !isErr(err, store.ErrNotFound) {
			t.Fatalf("GetPhoneTemplate = %v", err)
		}
		if got, err := s.Phone().ListPhoneTemplates(ctx, "b"); err != nil || len(got) != 0 {
			t.Fatalf("ListPhoneTemplates = %v, %v", got, err)
		}
		mustErrIs(t, s.Phone().DeletePhoneTemplate(ctx, "b", "t"), store.ErrNotFound)
		if _, err := s.Phone().FailPasswordlessCode(ctx, "b", "conn", "+14155550100", "link", now); !isErr(err, store.ErrNotFound) {
			t.Fatalf("FailPasswordlessCode = %v", err)
		}
		if _, err := s.Phone().ConsumePasswordlessCode(ctx, "b", "conn", "+14155550100", "link", "lh", 5, now); !isErr(err, store.ErrPrecondition) {
			t.Fatalf("ConsumePasswordlessCode = %v", err)
		}
		if _, err := s.Phone().PeekPasswordlessLink(ctx, "b", "lh", now); !isErr(err, store.ErrNotFound) {
			t.Fatalf("PeekPasswordlessLink = %v", err)
		}
		if got, err := s.Phone().FindUsersByPhone(ctx, "b", "conn", "+14155550100"); err != nil || len(got) != 0 {
			t.Fatalf("FindUsersByPhone = %v, %v", got, err)
		}
		mustNoErr(t, s.Phone().DeleteTenantPhone(ctx, "b"))
		// The owner's rows survived every foreign-tenant call.
		if _, err := s.Phone().GetPhoneProvider(ctx, "a", "p1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Phone().PeekPasswordlessLink(ctx, "a", "lh", now); err != nil {
			t.Fatal(err)
		}
	})
}

func isErr(err, target error) bool { return errors.Is(err, target) }
