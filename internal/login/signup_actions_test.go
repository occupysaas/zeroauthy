package login

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Hosted signups must supply transaction context and render safe Action outcomes.
func TestSignupPreRegistration(t *testing.T) {
	for _, tc := range []struct{ name, code, want string }{
		{"deny", `api.access.deny('private','Inscription refusée');`, "Inscription refusée"},
		{"throw", `throw Error('PRIVATE-secret');`, "exe_"},
		{"metadata", `if(!event.transaction || event.transaction.protocol !== 'oidc-basic-profile' || event.request.body.password) throw Error('bad transaction'); api.user.setAppMetadata('tier','paid');`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
			a := actionstest.NewOffline(t, e.st, w)
			tn, _ := e.st.Tenants().GetByName(context.Background(), "acme")
			a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "pre", `exports.onExecutePreUserRegistration=(event,api)=>{`+tc.code+`};`))
			e.h.Actions = a.Engine
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t, "screen_hint", "signup")
			rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"action@acme.test"}, "password": {"a good password 1"}})
			if tc.want != "" {
				if rec.Code != 400 || !strings.Contains(rec.Body.String(), tc.want) || strings.Contains(rec.Body.String(), "PRIVATE") {
					t.Fatalf("denied: %d %s", rec.Code, rec.Body)
				}
				if _, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "action@acme.test"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("denied user created: %v", err)
				}
			} else {
				u, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "action@acme.test")
				if rec.Code != 302 || err != nil || u.AppMetadata["tier"] != "paid" {
					t.Fatalf("created %d %+v %v %s", rec.Code, u, err, rec.Body)
				}
			}
		})
	}
}
