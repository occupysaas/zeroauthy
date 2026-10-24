package mgmt_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/protection"
)

type breachStub struct{ err error }

func (c breachStub) Check(context.Context, string) (bool, error) { return true, c.err }

// These status/code assertions are local A5 fallbacks, not observed Auth0 parity.
func TestBreachManagementPasswordWrites(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		e := newUsersEnv(t)
		u := e.mustCreate(t, map[string]any{"email": "old@x.test"})
		id := u["user_id"].(string)
		ctx := context.Background()
		before, _ := e.st.Users().Get(ctx, e.tn.ID, id)
		tn, _ := e.st.Tenants().Get(ctx, e.tn.ID)
		tn.ProtectionSettingsInitialized = true
		tn.ProtectionSettings.BreachedPassword.Enabled = true
		tn.ProtectionSettings.BreachedPassword.Stage.PreUserRegistration.Shields = []string{"block"}
		tn.ProtectionSettings.BreachedPassword.Stage.PreChangePassword.Shields = []string{"block"}
		e.st.Tenants().Update(ctx, tn)
		c := breachStub{}
		want := 400
		wantCode := "invalid_body"
		if unavailable {
			c.err = protection.ErrBreachUnavailable
			want = 503
			wantCode = "temporarily_unavailable"
		}
		e.h.Protection = &protection.Service{Store: e.st, BreachChecker: c}
		rec, body := e.create(t, map[string]any{"connection": dbConn, "email": "new@x.test", "password": "correct horse 1"})
		if rec.Code != want || body["errorCode"] != wantCode {
			t.Fatal("create", rec.Code, body)
		}
		rec, body = e.patch(t, id, map[string]any{"password": "another horse 2"})
		if rec.Code != want || body["errorCode"] != wantCode {
			t.Fatal("patch", rec.Code, body)
		}
		after, _ := e.st.Users().Get(ctx, e.tn.ID, id)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("user changed")
		}
	}
}
