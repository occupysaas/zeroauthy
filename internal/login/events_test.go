package login

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/ui"
)

type eventRecorder struct{ events []logs.Event }

func (c *eventRecorder) Record(_ context.Context, e logs.Event) { c.events = append(c.events, e) }
func TestAuthenticationEvents(t *testing.T) {
	for _, tc := range []struct{ login, password, code, user string }{{"alice@acme.test", "bad password", "fp", "known"}, {"missing@acme.test", "bad password", "fu", ""}, {"carol@acme.test", "carol password 1", "f", "known"}} {
		t.Run(tc.code, func(t *testing.T) {
			e := newEnv(t)
			capture := &eventRecorder{}
			e.h.Recorder = capture
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {tc.login}, "password": {tc.password}})
			if len(capture.events) != 1 {
				t.Fatalf("events=%+v", capture.events)
			}
			got := capture.events[0]
			if got.Type != tc.code || got.ClientID != "spa" || got.Connection != "Username-Password-Authentication" || got.ConnectionID == "" || got.Strategy != "auth0" || got.StrategyType != "database" || got.TenantID == "" || (tc.user != "" && got.UserID == "") {
				t.Fatalf("event=%+v", got)
			}
			for _, code := range logrules.Codes() {
				if code.Type == tc.code && got.Description != code.Description {
					t.Fatalf("description=%q", got.Description)
				}
			}
		})
	}
}

func TestHostedOutcomeEvents(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		run        func(*testing.T, *env)
	}{
		{"signup", "ss", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			b.do(t, "GET", "/u/signup?state="+state, nil)
			b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"new password 1"}})
		}},
		{"signup refused", "fs", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			b.do(t, "GET", "/u/signup?state="+state, nil)
			b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"x"}})
		}},
		{"reset initiation", "scpr", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"missing@acme.test"}})
		}},
		{"reset initiation failed", "fcpr", func(t *testing.T, e *env) {
			e.scripts.Funcs[store.ScriptGetUser] = func([]any) (any, error) {
				return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "unavailable"}
			}
			b := e.browser("acme.example.test")
			state, csrf := b.legacyBegin(t)
			b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"legacy@example.test"}})
		}},
		{"reset completion", "scp", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			completeReset(t, b, e.issueTicket(t, "alice@acme.test", time.Hour), "new password 123")
		}},
		{"reset refused", "fcp", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			completeReset(t, b, e.issueTicket(t, "alice@acme.test", time.Hour), "x")
		}},
		{"verification", "sv", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			u := e.user(t, "alice@acme.test")
			raw := e.issueVerification(t, u.UserID, "Username-Password-Authentication", "", false, "en", time.Hour)
			b.do(t, "GET", "/u/email-verification?ticket="+raw, nil)
		}},
		{"verification send failed", "fv", func(t *testing.T, e *env) {
			e.h.Verification.Mailer = failedEventMailer{}
			_ = e.h.Verification.Send(context.Background(), tenant.Resolved{Tenant: mustTenant(t, e, "acme"), Host: "acme.example.test"}, e.user(t, "alice@acme.test"), "spa", "en")
		}},
		{"social failure", "f", func(t *testing.T, e *env) {
			b := e.browser("acme.example.test")
			_, state, _ := b.begin(t)
			r := httptest.NewRequest("GET", "https://acme.example.test/u/login", nil)
			r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: mustTenant(t, e, "acme")}))
			e.h.socialFailure(httptest.NewRecorder(), r, &flow{res: tenant.Resolved{Tenant: mustTenant(t, e, "acme")}, txn: &store.AuthTransaction{ID: state, ClientID: "spa"}, view: ui.RequestTenant(r, mustTenant(t, e, "acme"), i18n.ForRequest(mustTenant(t, e, "acme"), r, ""))}, federation.ErrProviderDenied)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			capture := &eventRecorder{}
			e.h.Recorder = capture
			e.h.Verification.Recorder = capture
			tc.run(t, e)
			if len(capture.events) == 0 {
				t.Fatal("no event")
			}
			got := capture.events[len(capture.events)-1]
			if got.Type != tc.code || got.TenantID == "" || got.Description == "" {
				t.Fatalf("event=%+v", got)
			}
			if tc.code == "fv" && (got.Strategy != "auth0" || got.StrategyType != "database" || got.UserID == "") {
				t.Fatalf("verification attribution=%+v", got)
			}
			if tc.code == "ss" || tc.code == "scp" || tc.code == "sv" {
				if got.UserID == "" || got.ConnectionID == "" || got.Connection == "" || got.Strategy != "auth0" || got.StrategyType != "database" {
					t.Fatalf("event=%+v", got)
				}
			}
		})
	}
}

type failedEventMailer struct{}

func (failedEventMailer) Send(context.Context, email.Message) error {
	return errors.New("mail unavailable")
}

func TestLoginSucceedsWhenRecorderFull(t *testing.T) {
	e := newEnv(t)
	recorder := logs.NewRecorder(e.st, logs.Config{QueueSize: 1}, slog.New(slog.DiscardHandler))
	e.h.Recorder = recorder
	recorder.Record(context.Background(), logs.Event{TenantID: mustTenant(t, e, "acme").ID, Type: "s"})
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	// A notify-only breach event is recorded during the successful login, so
	// the success path itself exercises the saturated recorder.
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.BreachedPassword.Enabled = true
	tn.ProtectionSettings.BreachedPassword.Shields = []string{"admin_notification"}
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	e.h.Protection = &protection.Service{Store: e.st, BreachChecker: &breachStub{}}
	result := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if result.Code != 302 || b.cookies[session.CookieName] == nil || recorder.Dropped() == 0 {
		t.Fatalf("login=%d drops=%d", result.Code, recorder.Dropped())
	}
	if err := recorder.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCustomDBPrintedPasswordMasked(t *testing.T) {
	for _, password := range []string{"printed password 🔑", "abc", "猫"} {
		t.Run(password, func(t *testing.T) {
			e := newEnv(t)
			var sink syncBuffer
			log := slog.New(logscrub.Handler(slog.NewJSONHandler(&sink, nil)))
			runner, err := customdb.NewNodeRunner(config.CustomDB{}, log)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = runner.Close() })
			e.h.Log = log
			e.h.Database.Log = log
			e.h.Database.Scripts.Exec = runner
			e.h.Verification = nil
			tn := mustTenant(t, e, "acme")
			conn, err := e.st.Connections().GetByName(context.Background(), tn.ID, "Legacy-DB")
			if err != nil {
				t.Fatal(err)
			}
			conn.CustomScripts[store.ScriptGetUser] = `function getUser(e,cb){cb(null,null)}`
			conn.CustomScripts[store.ScriptCreate] = `function create(u,cb){console.log("signup-marker",u.password);cb(null)}`
			conn.CustomScripts[store.ScriptLogin] = `function login(e,p,cb){console.log("login-marker",p);cb(null,{user_id:"printed",email:e,name:p})}`
			conn.PasswordOptions.Complexity.MinLength = 1
			if err = e.st.Connections().Update(context.Background(), conn); err != nil {
				t.Fatal(err)
			}
			recorder := logs.NewRecorder(e.st, logs.Config{}, log)
			e.h.Recorder = recorder
			b := e.browser("acme.example.test")
			state, csrf := b.legacyBegin(t)
			b.do(t, "GET", "/u/signup?state="+state, nil)
			response := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@legacy.test"}, "password": {password}})
			if response.Code != 302 {
				t.Fatalf("signup=%d %s", response.Code, response.Body)
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := e.st.Logs().SearchLogs(context.Background(), tn.ID, nil, store.LogPage{PerPage: 100})
			if err != nil || len(events) != 1 {
				t.Fatal(events, err)
			}
			var body map[string]any
			if err = json.Unmarshal(events[0].Body, &body); err != nil {
				t.Fatal(err)
			}
			if body["user_name"] != logscrub.Marker || body["type"] != "ss" {
				t.Fatalf("stored=%s", events[0].Body)
			}
			deadline := time.Now().Add(time.Second)
			for !strings.Contains(sink.String(), "login-marker") && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			out := sink.String()
			if strings.Contains(out, password) || !strings.Contains(out, "signup-marker "+logscrub.Marker) || !strings.Contains(out, "login-marker "+logscrub.Marker) {
				t.Fatalf("server log=%s", out)
			}
		})
	}
}

func TestBreachOutcomeEvents(t *testing.T) {
	for _, tc := range []struct {
		stage string
		want  []string
	}{{"login", []string{"pwd_leak"}}, {"signup", []string{"signup_pwd_leak", "fs"}}, {"reset", []string{"reset_pwd_leak", "fcp"}}} {
		t.Run(tc.stage, func(t *testing.T) {
			e := newEnv(t)
			capture := &eventRecorder{}
			e.h.Recorder = capture
			tn := mustTenant(t, e, "acme")
			tn.ProtectionSettings.BreachedPassword.Enabled = true
			tn.ProtectionSettings.BreachedPassword.Shields = []string{"block"}
			tn.ProtectionSettings.BreachedPassword.Stage.PreUserRegistration.Shields = []string{"block"}
			tn.ProtectionSettings.BreachedPassword.Stage.PreChangePassword.Shields = []string{"block"}
			if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
				t.Fatal(err)
			}
			e.h.Protection = &protection.Service{Store: e.st, BreachChecker: &breachStub{}}
			b := e.browser("acme.example.test")
			if tc.stage == "reset" {
				completeReset(t, b, e.issueTicket(t, "alice@acme.test", time.Hour), "new password 123")
			} else {
				_, state, csrf := b.begin(t)
				form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}
				path := "/u/login"
				if tc.stage == "signup" {
					path = "/u/signup"
					form.Set("email", "new@acme.test")
					b.do(t, "GET", path+"?state="+state, nil)
				}
				b.do(t, "POST", path, form)
			}
			if len(capture.events) != len(tc.want) {
				t.Fatalf("events=%+v", capture.events)
			}
			for i, code := range tc.want {
				got := capture.events[i]
				if got.Type != code || got.ConnectionID == "" || got.Connection != "Username-Password-Authentication" || got.Strategy != "auth0" || got.StrategyType != "database" || got.Description == "" {
					t.Fatalf("event=%+v", got)
				}
			}
		})
	}
}

func TestDeviceActivationEvents(t *testing.T) {
	for _, tc := range []struct {
		code    string
		expired bool
	}{{"fdecc", false}, {"fdeac", true}} {
		t.Run(tc.code, func(t *testing.T) {
			e := newEnv(t)
			capture := &eventRecorder{}
			e.h.Recorder = capture
			dc := e.pendingCode(t, userCode)
			b := e.browser("acme.example.test")
			_, state, csrf := b.confirmPage(t, b.submitCode(t, userCode))
			if tc.expired {
				if _, err := e.st.DeviceCodes().Decide(context.Background(), dc.TenantID, dc.DeviceCodeHash, store.DeviceDecision{Status: store.DeviceCodeDenied}); err != nil {
					t.Fatal(err)
				}
			}
			b.do(t, "POST", "/device/confirmation", url.Values{"state": {state}, "csrf": {csrf}, "action": {"cancel"}})
			if len(capture.events) != 1 {
				t.Fatalf("events=%+v", capture.events)
			}
			got := capture.events[0]
			if got.Type != tc.code || got.ClientID != "tv" || got.TenantID == "" || got.Description == "" {
				t.Fatalf("event=%+v", got)
			}
		})
	}
}

func TestActionExecutionLinksOnSignupEvents(t *testing.T) {
	for _, tc := range []struct{ name, script, code string }{{"success", "", "ss"}, {"deny", "api.access.deny('private','refused');", "fs"}, {"throw", "throw Error('private failure');", "fs"}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			capture := &eventRecorder{}
			e.h.Recorder = capture
			a := actionstest.NewOffline(t, e.st, e.h.Database.Scripts.Wrapper)
			tn := mustTenant(t, e, "acme")
			a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "event-link", `exports.onExecutePreUserRegistration=(event,api)=>{`+tc.script+`};`))
			e.h.Actions = a.Engine
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t, "screen_hint", "signup")
			b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"new password 1"}})
			if len(capture.events) != 1 {
				t.Fatalf("events=%+v", capture.events)
			}
			got := capture.events[0]
			if got.Type != tc.code || len(got.ExecutionIDs) != 1 {
				t.Fatalf("event=%+v", got)
			}
			if _, err := e.st.Actions().GetExecution(context.Background(), tn.ID, got.ExecutionIDs[0]); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type breachResultStub struct {
	hit bool
	err error
}

func (s breachResultStub) Check(context.Context, string) (bool, error) { return s.hit, s.err }
func TestBreachMonitoringEvents(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hit   bool
		err   error
		count int
	}{{"notify-only hit", true, nil, 1}, {"clean password", false, nil, 0}, {"unavailable checker", false, protection.ErrBreachUnavailable, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			capture := &eventRecorder{}
			e.h.Recorder = capture
			tn := mustTenant(t, e, "acme")
			tn.ProtectionSettings.BreachedPassword.Enabled = true
			tn.ProtectionSettings.BreachedPassword.Shields = []string{"admin_notification"}
			if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
				t.Fatal(err)
			}
			e.h.Protection = &protection.Service{Store: e.st, BreachChecker: breachResultStub{tc.hit, tc.err}}
			b := e.browser("acme.example.test")
			_, state, csrf := b.begin(t)
			r := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
			if r.Code != 302 || len(capture.events) != tc.count {
				t.Fatalf("status=%d events=%+v", r.Code, capture.events)
			}
			if tc.count > 0 && capture.events[0].Type != "pwd_leak" {
				t.Fatalf("events=%+v", capture.events)
			}
		})
	}
}

func TestSocialCallbackFailureEventAttribution(t *testing.T) {
	s := newSocialEnv(t)
	capture := &eventRecorder{}
	s.h.Recorder = capture
	b := s.browser("acme.example.test")
	page := s.authorizeTo(t, b, "spa", "connection", "corp")
	start := b.do(t, "GET", strings.TrimPrefix(page, "https://acme.example.test"), nil)
	u, _ := url.Parse(start.Header().Get("Location"))
	result := b.do(t, "GET", "/login/callback?"+url.Values{"error": {"access_denied"}, "state": {u.Query().Get("state")}}.Encode(), nil)
	if result.Code != 401 || len(capture.events) != 1 {
		t.Fatalf("status=%d events=%+v", result.Code, capture.events)
	}
	got := capture.events[0]
	if got.Type != "f" || got.ClientID != "spa" || got.Connection != "corp" || got.ConnectionID != "con_corp" || got.Strategy != "oidc" || got.StrategyType != "enterprise" || got.UserID != "" {
		t.Fatalf("event=%+v", got)
	}
}
