package dbconn

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type breachStub struct {
	hit bool
	err error
}

func (c breachStub) Check(context.Context, string) (bool, error) { return c.hit, c.err }

// These status/code assertions are local A5 fallbacks, not observed Auth0 parity.
func TestBreachSignupBeforeCustomCreate(t *testing.T) {
	for _, bad := range []bool{false, true} {
		e := newEnv(t)
		ctx := context.Background()
		tn, _ := e.st.Tenants().Get(ctx, e.tenantID)
		tn.ProtectionSettings.BreachedPassword.Enabled = true
		tn.ProtectionSettings.BreachedPassword.Stage.PreUserRegistration.Shields = []string{"block"}
		e.st.Tenants().Update(ctx, tn)
		checker := breachStub{hit: true}
		want := 400
		wantCode := "password_leaked"
		if bad {
			checker = breachStub{err: protection.ErrBreachUnavailable}
			want = 503
			wantCode = "temporarily_unavailable"
		}
		e.h.Protection = &protection.Service{Store: e.st, BreachChecker: checker}
		calls := 0
		e.scripts.Funcs[store.ScriptGetUser] = func([]any) (any, error) { return nil, nil }
		e.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) { return map[string]any{"user_id": "new", "email": "new@acme.test"}, nil }
		e.scripts.Funcs[store.ScriptCreate] = func([]any) (any, error) { calls++; return map[string]any{"user_id": "new"}, nil }
		code, body, _ := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Legacy-DB","email":"new@acme.test","password":"a good password 1"}`)
		if code != want || body["error"] != wantCode || calls != 0 {
			t.Fatalf("status %d body %v create calls %d", code, body, calls)
		}
	}
}
