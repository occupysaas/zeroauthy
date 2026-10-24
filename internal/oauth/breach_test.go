package oauth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/passhash/passhashtest"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type breachStub struct {
	calls int
	err   error
}

func (c *breachStub) Check(context.Context, string) (bool, error) { c.calls++; return true, c.err }

// These status/code assertions are local A5 fallbacks, not observed Auth0 parity.
func TestBreachImportedLogin(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		f := newFixture(t)
		u := f.setImportedHash(t, passhashtest.PBKDF2("imported pw 12"))
		ctx := context.Background()
		tn, _ := f.st.Tenants().Get(ctx, u.TenantID)
		tn.ProtectionSettings.BreachedPassword.Enabled = true
		tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
		f.st.Tenants().Update(ctx, tn)
		c := &breachStub{}
		want := 401
		wantCode := "password_leaked"
		if unavailable {
			c.err = protection.ErrBreachUnavailable
			want = 503
			wantCode = "temporarily_unavailable"
		}
		f.h.Protection = &protection.Service{Store: f.st, BreachChecker: c}
		if code, _ := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "wrong")); code != 400 || c.calls != 0 {
			t.Fatal("unproved password checked", code, c.calls)
		}
		code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "imported pw 12"))
		if code != want || body["error"] != wantCode || body["access_token"] != nil || body["refresh_token"] != nil || c.calls != 1 {
			t.Fatal(code, body, c.calls)
		}
		upgraded, err := f.st.Users().Get(ctx, u.TenantID, u.UserID)
		if err != nil || upgraded.Identities[0].ImportedHash != "" || !strings.HasPrefix(upgraded.Identities[0].PasswordHash, "$argon2id$") {
			t.Fatal("verified imported hash upgrade lost", err)
		}
	}
}

func TestBreachLegacyGrantPreservesProfile(t *testing.T) {
	for _, exists := range []bool{false, true} {
		for _, unavailable := range []bool{false, true} {
			f := newFixture(t)
			ctx := context.Background()
			tn, err := f.st.Tenants().Get(ctx, f.tenantID(t, "acme"))
			if err != nil {
				t.Fatal(err)
			}
			f.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
				return map[string]any{"user_id": 42, "email": "dave@legacy.test", "name": "before"}, nil
			}
			conn, err := f.st.Connections().GetByName(ctx, tn.ID, "Legacy-DB")
			if err != nil {
				t.Fatal(err)
			}
			var before *store.User
			if exists {
				before, err = f.h.Database.Login(ctx, conn, "dave@legacy.test", "dave legacy 1")
				if err != nil {
					t.Fatal(err)
				}
			}
			f.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
				return map[string]any{"user_id": 42, "email": "dave@legacy.test", "name": "changed"}, nil
			}
			tn.ProtectionSettings.BreachedPassword.Enabled = true
			tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
			if err := f.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			c := &breachStub{}
			want := 401
			if unavailable {
				c.err = protection.ErrBreachUnavailable
				want = 503
			}
			f.h.Protection = &protection.Service{Store: f.st, BreachChecker: c}
			rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "dave legacy 1")})
			if rec.Code != want || body["access_token"] != nil || body["refresh_token"] != nil {
				t.Fatal(rec.Code, body)
			}
			after, err := f.st.Users().Get(ctx, tn.ID, "auth0|42")
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

func TestBreachCustomImportPreservesState(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, unavailable := range []bool{false, true} {
			f := newFixture(t)
			ctx := context.Background()
			tn, err := f.st.Tenants().Get(ctx, f.tenantID(t, "acme"))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := f.st.Connections().GetByName(ctx, tn.ID, "Legacy-DB")
			if err != nil {
				t.Fatal(err)
			}
			conn.ImportMode = true
			conn.PasswordOptions.History.Active = true
			conn.PasswordOptions.History.Size = 3
			if err := f.st.Connections().Update(ctx, conn); err != nil {
				t.Fatal(err)
			}
			var before *store.User
			if existing {
				before = &store.User{TenantID: tn.ID, UserID: "auth0|42", Email: "dave@legacy.test", Name: "unchanged", Identities: []store.Identity{{Provider: store.StrategyDatabase, Connection: conn.Name, UserID: "42"}}}
				if err := f.st.Users().Create(ctx, before); err != nil {
					t.Fatal(err)
				}
				before, err = f.st.Users().Get(ctx, tn.ID, before.UserID)
				if err != nil {
					t.Fatal(err)
				}
			}
			f.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) { return map[string]any{"user_id": 42, "email": "dave@legacy.test"}, nil }
			tn.ProtectionSettings.BreachedPassword.Enabled = true
			tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
			if err := f.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			c := &breachStub{}
			want := 401
			if unavailable {
				c.err = protection.ErrBreachUnavailable
				want = 503
			}
			f.h.Protection = &protection.Service{Store: f.st, BreachChecker: c}
			rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: legacyRealm("dave@legacy.test", "dave legacy 1")})
			if rec.Code != want || body["access_token"] != nil {
				t.Fatal(rec.Code, body)
			}
			after, err := f.st.Users().Get(ctx, tn.ID, "auth0|42")
			if existing {
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("import changed user/password", err)
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Fatal("import created user", err)
			}
			history, err := f.st.PasswordHistories().List(ctx, tn.ID, "auth0|42")
			if err != nil || len(history) != 0 {
				t.Fatal("import created history", err)
			}
		}
	}
}
