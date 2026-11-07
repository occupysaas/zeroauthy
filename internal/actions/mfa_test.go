package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func runMFAAction(t *testing.T, body string, customize bool) (*actions.Result, error, *harness) {
	t.Helper()
	h := newHarness(t)
	a := h.action("t1", trigLogin, "mfa", `exports.onExecutePostLogin=(event,api)=>{`+body+`};`, nil, false)
	h.bind("t1", trigLogin, a)
	in := h.loginInput("t1")
	in.Tenant.Tenant.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": customize}
	r, err := h.eng.PostLogin(context.Background(), in)
	return r, err, h
}
func requireMFAError(t *testing.T, err error, h *harness, contains string) {
	t.Helper()
	var fe *actions.ErrFlow
	if !errors.As(err, &fe) {
		t.Fatalf("expected closed execution, got %v", err)
	}
	ex := h.execution("t1", fe.ExecutionID)
	if len(ex.Results) != 1 || ex.Results[0].ErrorID != "invalid_api_call" || !strings.Contains(ex.Results[0].ErrorMsg, contains) {
		t.Fatalf("execution=%+v", ex.Results)
	}
}
func TestMultifactorEnableProviders(t *testing.T) {
	for _, p := range []string{"any", "google-authenticator", "guardian", "none"} {
		t.Run(p, func(t *testing.T) {
			r, err, _ := runMFAAction(t, fmt.Sprintf(`api.multifactor.enable(%q);`, p), false)
			if err != nil || r.Effects.MFA == nil || r.Effects.MFA.Provider != p || r.Effects.MFA.AllowRememberBrowser {
				t.Fatalf("result=%+v err=%v", r, err)
			}
		})
	}
	r, err, _ := runMFAAction(t, `api.multifactor.enable('any',{allowRememberBrowser:true});`, false)
	if err != nil || !r.Effects.MFA.AllowRememberBrowser {
		t.Fatalf("remember=%+v %v", r, err)
	}
	_, err, h := runMFAAction(t, `api.multifactor.enable('duo');`, false)
	requireMFAError(t, err, h, "Duo")
}
func TestChallengeWithRequiresTenantFlag(t *testing.T) {
	_, err, h := runMFAAction(t, `api.authentication.challengeWith({type:'otp'});`, false)
	requireMFAError(t, err, h, "customize_mfa_in_postlogin_action")
}
func TestChallengeWithAndEnableConflict(t *testing.T) {
	for _, body := range []string{`api.multifactor.enable('any');api.authentication.challengeWith({type:'otp'});`, `api.authentication.challengeWith({type:'otp'});api.multifactor.enable('none');`} {
		_, err, h := runMFAAction(t, body, true)
		requireMFAError(t, err, h, "cannot be combined")
	}
}
func TestChallengeWithAdditionalFactors(t *testing.T) {
	r, err, _ := runMFAAction(t, `api.authentication.challengeWith({type:'otp'},{additionalFactors:[{type:'email'},{type:'recovery-code'}]});`, true)
	if err != nil || r.Effects.MFA == nil || r.Effects.MFA.Mode != "challenge" || !reflect.DeepEqual(r.Effects.MFA.Factors, [][]string{{"otp", "email", "recovery-code"}}) {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestEnrollWithAny(t *testing.T) {
	for _, call := range []string{`enrollWithAny([{type:'otp'},{type:'email'}])`, `enrollWith({type:'otp'},{additionalFactors:[{type:'email'}]})`} {
		r, err, _ := runMFAAction(t, `api.authentication.`+call+`;`, true)
		if err != nil || r.Effects.MFA == nil || r.Effects.MFA.Mode != "enroll" || !reflect.DeepEqual(r.Effects.MFA.Factors, [][]string{{"otp", "email"}}) {
			t.Fatalf("%+v %v", r, err)
		}
	}
}
func TestPhoneFactorUnavailable(t *testing.T) {
	for _, factor := range []string{"push-notification"} {
		_, err, h := runMFAAction(t, fmt.Sprintf(`api.authentication.challengeWith({type:%q});`, factor), true)
		requireMFAError(t, err, h, "unavailable")
	}
}
func TestChallengeWithPhone(t *testing.T) {
	r, err, _ := runMFAAction(t, `api.authentication.challengeWith({type:'phone',options:{preferredMethod:'voice'}});`, true)
	if err != nil || r.Effects.MFA == nil || r.Effects.MFA.Mode != "challenge" || !reflect.DeepEqual(r.Effects.MFA.Factors, [][]string{{"phone"}}) || r.Effects.MFA.PhonePreferredMethod != "voice" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err, _ = runMFAAction(t, `api.authentication.challengeWith({type:'otp'},{additionalFactors:[{type:'phone'}]});`, true)
	if err != nil || !reflect.DeepEqual(r.Effects.MFA.Factors, [][]string{{"otp", "phone"}}) || r.Effects.MFA.PhonePreferredMethod != "" {
		t.Fatalf("additional phone %+v %v", r, err)
	}
	r, err, _ = runMFAAction(t, `api.authentication.enrollWith({type:'phone',options:{preferredMethod:'both'}});`, true)
	if err != nil || r.Effects.MFA.Mode != "enroll" || r.Effects.MFA.PhonePreferredMethod != "both" {
		t.Fatalf("enroll phone %+v %v", r, err)
	}
	for _, call := range []string{`challengeWith({type:'phone',options:{preferredMethod:'fax'}})`, `challengeWith({type:'otp',options:{preferredMethod:'sms'}})`, `challengeWith({type:'phone',options:{other:true}})`} {
		_, err, h := runMFAAction(t, `try{api.authentication.`+call+`;}catch(e){}`, true)
		requireMFAError(t, err, h, "")
	}
}
func TestChallengeWithInvalidArguments(t *testing.T) {
	for _, call := range []string{`multifactor.enable()`, `multifactor.enable('unknown')`, `multifactor.enable('any',null)`, `multifactor.enable('any',{allowRememberBrowser:'yes'})`, `authentication.challengeWith({type:'otp',secret:'no'})`, `authentication.challengeWith({type:'bad'})`, `authentication.challengeWithAny([])`, `authentication.challengeWithAny([{type:'otp'}],{})`, `authentication.enrollWith({type:'email'},{additionalFactors:null})`, `authentication.challengeWith(null)`, `authentication.enrollWithAny('otp')`} {
		t.Run(call, func(t *testing.T) {
			_, err, h := runMFAAction(t, `try{api.`+call+`;}catch(e){}`, true)
			requireMFAError(t, err, h, "")
		})
	}
}
func TestEnrolledFactorsInEvent(t *testing.T) {
	h := newHarness(t)
	for i, typ := range []string{"totp", "email", "recovery-code", "webauthn-roaming", "phone"} {
		if err := h.st.MFA().CreateAuthenticator(context.Background(), &store.Authenticator{TenantID: "t1", UserID: "auth0|u1", ID: fmt.Sprint("factor", i), Type: typ, Confirmed: true, Email: "secret@example.test", Phone: "+15555555555", CodeHash: "never-public", SealedSecret: []byte("secret")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.st.MFA().CreateAuthenticator(context.Background(), &store.Authenticator{TenantID: "t1", UserID: "auth0|u1", ID: "pending", Type: "totp"}); err != nil {
		t.Fatal(err)
	}
	a := h.action("t1", trigLogin, "event", `exports.onExecutePostLogin=(event,api)=>api.idToken.setCustomClaim('urn:factors',event.user.enrolledFactors);`, nil, false)
	h.bind("t1", trigLogin, a)
	r := h.mustPostLogin("t1")
	got := fmt.Sprint(r.Effects.IDClaims["urn:factors"])
	for _, typ := range []string{"otp", "email", "recovery-code", "webauthn-roaming", "phone"} {
		if !strings.Contains(got, typ) {
			t.Fatalf("missing %s in %s", typ, got)
		}
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "+155") || strings.Contains(got, "never-public") || strings.Count(got, "type:otp") != 1 {
		t.Fatal(got)
	}
}
func TestMFAMethodInEvent(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "method", `exports.onExecutePostLogin=(event,api)=>api.idToken.setCustomClaim('urn:methods',event.authentication.methods);`, nil, false)
	h.bind("t1", trigLogin, a)
	in := h.loginInput("t1")
	at := h.clock().Add(-time.Minute)
	in.Session = &store.LoginSession{ID: "session", TenantID: "t1", UserID: in.User.UserID, MFAAt: at}
	r, err := h.eng.PostLogin(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	methods := r.Effects.IDClaims["urn:methods"].([]any)
	if len(methods) != 1 || fmt.Sprint(methods[0]) != fmt.Sprint(map[string]any{"name": "mfa", "timestamp": at.Format(time.RFC3339Nano)}) {
		t.Fatalf("methods=%v", methods)
	}
}

func TestMFAMethodAndChallengeWithRedirectContinuation(t *testing.T) {
	h := newHarness(t)
	code := `exports.onExecutePostLogin=(event,api)=>{api.authentication.challengeWith({type:'otp'});api.redirect.sendUserTo('https://external.test/');};exports.onContinuePostLogin=(event,api)=>{api.idToken.setCustomClaim('urn:methods',event.authentication.methods);api.idToken.setCustomClaim('urn:factors',event.user.enrolledFactors);};`
	a := h.action("t1", trigLogin, "redirect-mfa", code, nil, false)
	h.bind("t1", trigLogin, a)
	in := h.loginInput("t1")
	in.CanRedirect = true
	in.Session = &store.LoginSession{ID: "mfa-session", TenantID: "t1", UserID: in.User.UserID, ExpiresAt: h.clock().Add(time.Hour)}
	in.Tenant.Tenant.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	r, err := h.eng.PostLogin(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Redirect == nil {
		t.Fatal("missing redirect")
	}
	if err = h.st.MFA().CreateAuthenticator(context.Background(), &store.Authenticator{TenantID: "t1", UserID: in.User.UserID, ID: "new-factor", Type: "totp", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	in.Session.MFAAt = h.clock()
	r, err = h.eng.ContinuePostLogin(context.Background(), "t1", r.Redirect.Query["state"], in.Session, actions.RequestInfo{Hostname: in.Tenant.Host, Origin: in.Tenant.Origin()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Effects.MFA == nil || r.Effects.MFA.Mode != "challenge" || len(r.Effects.IDClaims["urn:methods"].([]any)) != 1 || !strings.Contains(fmt.Sprint(r.Effects.IDClaims["urn:factors"]), "otp") {
		t.Fatalf("continuation=%+v", r)
	}
}

func TestChallengeWithAndEnableAcrossActions(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "first-mfa", `exports.onExecutePostLogin=(event,api)=>api.multifactor.enable('none');`, nil, false)
	b := h.action("t1", trigLogin, "second-mfa", `exports.onExecutePostLogin=(event,api)=>api.authentication.challengeWith({type:'otp'});`, nil, false)
	h.bind("t1", trigLogin, a, b)
	in := h.loginInput("t1")
	in.Tenant.Tenant.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	_, err := h.eng.PostLogin(context.Background(), in)
	var fe *actions.ErrFlow
	if !errors.As(err, &fe) {
		t.Fatalf("mixed effects accepted %v", err)
	}
	ex := h.execution("t1", fe.ExecutionID)
	if len(ex.Results) != 2 || ex.Results[1].ErrorID != "invalid_api_call" {
		t.Fatalf("results=%+v", ex.Results)
	}
}

func TestChallengeWithInvalidArgumentsCannotBeCaughtOrHidden(t *testing.T) {
	for _, body := range []string{`try{api.authentication.challengeWith({type:1n});}catch(e){}`, `const circular={type:'otp'};circular.self=circular;try{api.authentication.challengeWith(circular);}catch(e){}`, `api.authentication.challengeWith({type:'invalid'});throw Error('later');`} {
		_, err, h := runMFAAction(t, body, true)
		requireMFAError(t, err, h, "")
	}
}

func TestPhoneMethodsInTransaction(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "phone-tx", Name: "phone-tx"}); err != nil {
		t.Fatal(err)
	}
	g, _ := st.MFA().GetGuardian(ctx, "phone-tx")
	g.Factors["sms"] = true
	if err := st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	if err := st.Phone().CreatePhoneProvider(ctx, &store.PhoneProvider{TenantID: "phone-tx", ID: "p", Name: "custom", Configuration: json.RawMessage(`{"delivery_methods":["text"]}`)}); err != nil {
		t.Fatal(err)
	}
	engine := &actions.Engine{Store: st}
	svc := mfa.NewService(st, nil, nil, nil, nil, nil)
	svc.Phone = &phone.Dispatcher{Store: st, Actions: engine}
	if err := st.WithTx(ctx, func(tx store.Store) error {
		methods, err := svc.WithStore(tx).PhoneMethods(ctx, "phone-tx")
		if len(methods) != 0 {
			t.Fatal("unbound Action offered")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWebAuthnTicketAndActions(t *testing.T) {
	for _, factor := range []string{"webauthn-roaming", "webauthn-platform"} {
		for _, call := range []string{"challengeWith", "enrollWith"} {
			r, err, _ := runMFAAction(t, `api.authentication.`+call+`({type:'`+factor+`'});`, true)
			if err != nil || r.Effects.MFA == nil || !reflect.DeepEqual(r.Effects.MFA.Factors, [][]string{{factor}}) {
				t.Fatalf("%s/%s: %+v %v", call, factor, r, err)
			}
		}
	}
}
