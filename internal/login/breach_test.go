package login

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type breachStub struct {
	err   error
	calls int
}

func (c *breachStub) Check(context.Context, string) (bool, error) { c.calls++; return true, c.err }
func TestBreachResetPreservesState(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		e := newEnv(t)
		ctx := context.Background()
		tn := mustTenant(t, e, "acme")
		tn.ProtectionSettings.BreachedPassword.Enabled = true
		tn.ProtectionSettings.BreachedPassword.Stage.PreChangePassword.Shields = []string{"block"}
		e.st.Tenants().Update(ctx, tn)
		c := &breachStub{}
		want := 400
		if unavailable {
			c.err = protection.ErrBreachUnavailable
			want = 503
		}
		e.h.Protection = &protection.Service{Store: e.st, BreachChecker: c}
		before := e.user(t, "alice@acme.test")
		if err := e.st.PasswordHistories().Add(ctx, tn.ID, before.UserID, []byte("history sentinel"), 3); err != nil {
			t.Fatal(err)
		}
		historyBefore, err := e.st.PasswordHistories().List(ctx, tn.ID, before.UserID)
		if err != nil {
			t.Fatal(err)
		}
		cookie, rt := e.signedInElsewhere(t, "alice@acme.test")
		ticket := e.issueTicket(t, "alice@acme.test", time.Hour)
		b := e.browser("acme.example.test")
		page := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		csrf := csrfField.FindStringSubmatch(page.Body.String())
		if csrf == nil {
			t.Fatal(page.Body.String())
		}
		rec := b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {ticket}, "csrf": {csrf[1]}, "password": {"new password 123"}, "password_confirm": {"new password 123"}})
		if rec.Code != want {
			t.Fatal(rec.Code, rec.Body.String())
		}
		after := e.user(t, "alice@acme.test")
		historyAfter, err := e.st.PasswordHistories().List(ctx, tn.ID, before.UserID)
		if err != nil || !reflect.DeepEqual(historyBefore, historyAfter) {
			t.Fatal("history changed", err)
		}
		if !e.sessionAlive(t, cookie) {
			t.Fatal("session revoked")
		}
		token, err := e.st.RefreshTokens().GetByTokenHash(ctx, tn.ID, rt.TokenHash)
		if err != nil || token.RevokedAt != nil {
			t.Fatal("refresh revoked", err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("user changed")
		}
		tk, err := e.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(ticket))
		if err != nil || tk.UsedAt != nil {
			t.Fatal("ticket consumed", tk, err)
		}
	}
}
func TestBreachHostedLoginAndSignup(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
	tn.ProtectionSettings.BreachedPassword.Stage.PreUserRegistration.Shields = []string{"block"}
	e.st.Tenants().Update(ctx, tn)
	c := &breachStub{}
	e.h.Protection = &protection.Service{Store: e.st, BreachChecker: c}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}
	rec := b.do(t, "POST", "/u/login", form)
	if rec.Code != 401 || rec.Header().Get("Location") != "" || c.calls != 1 {
		t.Fatal("login", rec.Code, c.calls)
	}
	form.Set("email", "new@acme.test")
	rec = b.do(t, "POST", "/u/signup", form)
	if rec.Code != 400 || c.calls != 2 {
		t.Fatal("signup", rec.Code, c.calls)
	}
}

func TestBreachLegacyHostedPreservesProfile(t *testing.T) {
	for _, exists := range []bool{false, true} {
		for _, unavailable := range []bool{false, true} {
			e := newEnv(t)
			ctx := context.Background()
			tn := mustTenant(t, e, "acme")
			e.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
				return map[string]any{"user_id": 42, "email": "dave@legacy.test", "name": "before"}, nil
			}
			conn, err := e.st.Connections().GetByName(ctx, tn.ID, "Legacy-DB")
			if err != nil {
				t.Fatal(err)
			}
			var before *store.User
			if exists {
				before, err = e.h.Database.Login(ctx, conn, "dave@legacy.test", "dave legacy 1")
				if err != nil {
					t.Fatal(err)
				}
			}
			e.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
				return map[string]any{"user_id": 42, "email": "dave@legacy.test", "name": "changed"}, nil
			}
			tn.ProtectionSettings.BreachedPassword.Enabled = true
			tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
			if err := e.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			c := &breachStub{}
			want := 401
			if unavailable {
				c.err = protection.ErrBreachUnavailable
				want = 503
			}
			e.h.Protection = &protection.Service{Store: e.st, BreachChecker: c}
			b := e.browser("acme.example.test")
			state, csrf := b.legacyBegin(t)
			rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"dave@legacy.test"}, "password": {"dave legacy 1"}})
			if rec.Code != want || rec.Header().Get("Location") != "" || b.cookies[session.CookieName] != nil {
				t.Fatal("session issued or wrong refusal", rec.Code)
			}
			after, err := e.st.Users().Get(ctx, tn.ID, "auth0|42")
			if exists {
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("legacy profile changed", err)
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Fatal("legacy profile created", err)
			}
		}
	}
}
