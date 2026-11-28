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

// Bound pre-registration Actions without a runtime must fail closed, as the
// reset page does (M-1); an unbound tenant still signs up.
func TestSignupPreRegistrationWithoutEngine(t *testing.T) {
	for _, bound := range []bool{true, false} {
		e := newEnv(t)
		w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
		a := actionstest.NewOffline(t, e.st, w)
		tn, _ := e.st.Tenants().GetByName(context.Background(), "acme")
		if bound {
			a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "pre", `exports.onExecutePreUserRegistration=()=>{};`))
		}
		e.h.Actions = nil
		b := e.browser("acme.example.test")
		_, state, csrf := b.begin(t, "screen_hint", "signup")
		rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"action@acme.test"}, "password": {"a good password 1"}})
		_, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "action@acme.test")
		if bound && (rec.Code != 400 || !errors.Is(err, store.ErrNotFound)) {
			t.Fatalf("bound without engine: %d %v", rec.Code, err)
		}
		if !bound && (rec.Code != 302 || err != nil) {
			t.Fatalf("unbound without engine: %d %v %s", rec.Code, err, rec.Body)
		}
	}
}

func TestSignupFieldsInEvent(t *testing.T) {
	e := newEnv(t)
	setPartials(t, e, map[string]map[string]map[string]string{"signup": {"signup": {"form-content-end": `<input aria-label="Company" name="ulp-company">`}}})
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	a := actionstest.NewOffline(t, e.st, w)
	tn := mustTenant(t, e, "acme")
	a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "fields", `exports.onExecutePreUserRegistration=(event,api)=>{if(event.request.body['ulp-company']!=='TransientCompany' || event.request.body.csrf || event.request.body.state)throw Error('bad body');};`))
	e.h.Actions = a.Engine
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"fields@acme.test"}, "password": {"a good password 1"}, "ulp-company": {"TransientCompany"}})
	if rec.Code != 302 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	u, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "fields@acme.test")
	if err != nil || len(u.UserMetadata) > 0 || strings.Contains(e.logs.String(), "TransientCompany") {
		t.Fatalf("stored/logged transient field: %+v %v", u, err)
	}
}
func TestValidationErrorOnField(t *testing.T) {
	e := newEnv(t)
	setPartials(t, e, map[string]map[string]map[string]string{"signup": {"signup": {"form-content-end": `<input aria-label="Company" name="ulp-company">`}}})
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	a := actionstest.NewOffline(t, e.st, w)
	tn := mustTenant(t, e, "acme")
	a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "validate", `exports.onExecutePreUserRegistration=(event,api)=>api.validation.error('company','Please choose another company');`))
	e.h.Actions = a.Engine
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"fields@acme.test"}, "password": {"a good password 1"}, "ulp-company": {"TransientCompany"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "Please choose another company") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if err != nil || txn.HostedState.PromptFields["ulp-company"] != "TransientCompany" {
		t.Fatalf("lost fields %+v %v", txn, err)
	}
}
func TestSignupSetUserId(t *testing.T) {
	e := newEnv(t)
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	a := actionstest.NewOffline(t, e.st, w)
	tn := mustTenant(t, e, "acme")
	a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "id", `exports.onExecutePreUserRegistration=(event,api)=>api.user.setUserId('external-123');`))
	e.h.Actions = a.Engine
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"customid@acme.test"}, "password": {"a good password 1"}})
	u, err := e.st.Users().Get(context.Background(), tn.ID, "auth0|external-123")
	if rec.Code != 302 || err != nil || u.Identities[0].UserID != "external-123" {
		t.Fatalf("%d %+v %v %s", rec.Code, u, err, rec.Body.String())
	}
	b = e.browser("acme.example.test")
	_, state, csrf = b.begin(t, "screen_hint", "signup")
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"collision@acme.test"}, "password": {"a good password 1"}})
	if rec.Code == 302 {
		t.Fatal("duplicate id accepted")
	}
}
