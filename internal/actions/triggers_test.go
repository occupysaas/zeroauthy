package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// The runner and validator must agree on each trigger's capabilities; a
// wrong handler, leaked capability or missing command fails these real runs.
func TestTriggerAPIs(t *testing.T) {
	e, buildID := triggerTestEngine(t)
	cases := []struct{ trigger, handler, code, ops string }{
		{"post-login", "onExecutePostLogin", `api.accessToken.setCustomClaim('urn:test', true); api.transaction.addTargetScope('read');`, "accessToken.setCustomClaim,transaction.addTargetScope"},
		{"credentials-exchange", "onExecuteCredentialsExchange", `api.access.deny('invalid_scope', 'reason'); api.transaction.clearTargetScopes();`, "access.deny,transaction.clearTargetScopes"},
		{"pre-user-registration", "onExecutePreUserRegistration", `const chained = api.user.setAppMetadata('plan', 'pro'); if (chained.accessToken) throw Error('chain leaked token API'); api.user.setUserMetadata('color', 'blue'); api.access.deny('policy', 'Bitte bestätigen'); api.validation.error('invalid_signup','reason'); api.cache.set('k','v'); if(api.cache.get('k').value !== 'v') throw Error('cache read'); api.cache.delete('k');`, "user.setAppMetadata,user.setUserMetadata,access.deny,validation.error,cache.set,cache.delete"},
		{"post-user-registration", "onExecutePostUserRegistration", `if (Object.keys(api).join(',') !== 'cache') throw Error('cache only'); api.cache.set('k','v'); if(api.cache.get('k').value !== 'v') throw Error('cache read'); api.cache.delete('k');`, "cache.set,cache.delete"},
		{"post-change-password", "onExecutePostChangePassword", `if (Object.keys(api).join(',') !== 'cache') throw Error('cache only'); api.cache.set('k','v'); api.cache.delete('k');`, "cache.set,cache.delete"},
		{"password-reset-post-challenge", "onExecutePostChallenge", `if(!api.redirect.canRedirect()) throw Error('canRedirect'); api.transaction.setResultUrl('https://app.test/done?keep=yes', {query:{status:'ok',count:2,valid:true}}); api.redirect.sendUserTo('https://app.test/challenge'); const tok = api.redirect.encodeToken({secret:'test-secret',payload:{state:'fixture-state'}}); event.request.query={session_token:tok}; if(api.redirect.validateToken({secret:'test-secret'}).state !== 'fixture-state') throw Error('token validation'); api.cache.set('k','v'); if(api.cache.get('k').value !== 'v') throw Error('cache read'); api.cache.delete('k'); api.access.deny('policy');`, "transaction.setResultUrl,redirect.sendUserTo,cache.set,cache.delete,access.deny"},
		{"custom-email-provider", "onExecuteCustomEmailProvider", `api.notification.retry('temporary'); api.notification.drop('permanent'); api.cache.set('k','v'); if(api.cache.get('k').value !== 'v') throw Error('cache read'); api.cache.delete('k');`, "notification.retry,notification.drop,cache.set,cache.delete"},
	}
	for _, tc := range cases {
		t.Run(tc.trigger, func(t *testing.T) {
			if got := handlerFor(tc.trigger); got != tc.handler {
				t.Errorf("handler=%s want %s", got, tc.handler)
			}
			a, out, err := triggerTestRun(t, e, buildID, tc.trigger, tc.handler, tc.code)
			if err != nil {
				t.Fatalf("trigger API: %v", err)
			}
			var ops []string
			for _, c := range out.commands {
				ops = append(ops, c.Op)
			}
			if got := strings.Join(ops, ","); got != tc.ops {
				t.Errorf("ops=%s want %s", got, tc.ops)
			}
			if tc.trigger == "pre-user-registration" {
				if got := mustMarshal(t, a.denied); !strings.Contains(got, `"UserMessage":"Bitte bestätigen"`) || !strings.Contains(got, `"Reason":"policy"`) {
					t.Errorf("denial=%s", got)
				}
			}
		})
	}
	for _, member := range []string{"authentication.challengeWith", "authentication.challengeWithAny", "prompt.render"} {
		t.Run("caught_"+member, func(t *testing.T) {
			_, out, err := triggerTestRun(t, e, buildID, "password-reset-post-challenge", "onExecutePostChallenge", `try { api.`+member+`({type:'otp'}); } catch(e) {}`)
			if errorID(err) != "unsupported_api" || out == nil || len(out.commands) != 1 || out.commands[0].Op != "unsupported" {
				t.Fatalf("out=%+v error=%v", out, err)
			}
		})
	}

	t.Run("notification_last_wins_and_character_limit", func(t *testing.T) {
		for _, calls := range []struct{ code, kind, reason string }{
			{`api.notification.retry('temporary'); api.notification.drop('永久');`, "drop", "永久"},
			{`api.notification.drop('never'); api.notification.retry('ä'.repeat(1025));`, "retry", strings.Repeat("ä", 1024)},
		} {
			a, _, err := triggerTestRun(t, e, buildID, "custom-email-provider", "onExecuteCustomEmailProvider", calls.code)
			if err != nil {
				t.Fatal(err)
			}
			if a.notification == nil || a.notification.Kind != calls.kind || a.notification.Reason != calls.reason {
				t.Errorf("notification=%+v", a.notification)
			}
		}
	})
	t.Run("result_url_query_and_localhost", func(t *testing.T) {
		for _, tc := range []struct{ code, want string }{
			{`api.transaction.setResultUrl('https://app.test/done?keep=yes&status=old#end',{query:{status:'ok',count:2,valid:true}});`, "https://app.test/done?count=2&keep=yes&status=ok&valid=true#end"},
			{`api.transaction.setResultUrl('http://localhost:3000/done');`, "http://localhost:3000/done"},
		} {
			a, _, err := triggerTestRun(t, e, buildID, "password-reset-post-challenge", "onExecutePostChallenge", tc.code)
			if err != nil || a.resultURL != tc.want {
				t.Errorf("url=%s err=%v want %s", a.resultURL, err, tc.want)
			}
		}
	})
	t.Run("localized_denials", func(t *testing.T) {
		for _, tc := range []struct{ trigger, handler, code, reason, message string }{
			{"pre-user-registration", "onExecutePreUserRegistration", `api.access.deny('Règle','Bitte bestätigen');`, "Règle", "Bitte bestätigen"},
			{"pre-user-registration", "onExecutePreUserRegistration", `api.validation.error('invalid_signup','確認してください');`, "確認してください", "確認してください"},
			{"password-reset-post-challenge", "onExecutePostChallenge", `api.access.deny('Bestätigen');`, "Bestätigen", ""},
		} {
			a, _, err := triggerTestRun(t, e, buildID, tc.trigger, tc.handler, tc.code)
			if err != nil || a.denied == nil || a.denied.Reason != tc.reason || a.denied.UserMessage != tc.message {
				t.Errorf("denial=%+v err=%v", a.denied, err)
			}
		}
	})
	t.Run("reset_continue_handler", func(t *testing.T) {
		_, _, err := triggerTestRun(t, e, buildID, "password-reset-post-challenge", "onContinuePostChallenge", `api.transaction.setResultUrl('https://app.test/done');`)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("invalid_result_url", func(t *testing.T) {
		for _, raw := range []string{"http://app.test/done", "javascript:alert(1)", "/relative", "https://user:secret@app.test/done"} {
			_, _, err := triggerTestRun(t, e, buildID, "password-reset-post-challenge", "onExecutePostChallenge", fmt.Sprintf("api.transaction.setResultUrl(%q);", raw))
			if errorID(err) != "invalid_api_call" {
				t.Errorf("%s: %v", raw, err)
			}
		}
	})

	t.Run("run_results", func(t *testing.T) {
		for _, tc := range []struct{ trigger, handler, code string }{
			{"password-reset-post-challenge", "onExecutePostChallenge", `api.transaction.setResultUrl('https://app.test/done');`},
			{"custom-email-provider", "onExecuteCustomEmailProvider", `api.notification.retry('temporary');api.notification.drop('permanent');`},
		} {
			f := &flow{tenantID: "t", trigger: tc.trigger, handler: tc.handler, acc: newAccum(tc.trigger, nil, nil, false), cache: newActionCache()}
			f.units = []unit{{name: "result", actionID: "result", versionKey: tc.trigger, buildID: buildID, code: "exports." + tc.handler + "=async(event,api)=>{" + tc.code + "};"}}
			f.event = func() map[string]any { return map[string]any{} }
			result, err := e.run(context.Background(), f, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.trigger == "password-reset-post-challenge" && result.ResultURL != "https://app.test/done" {
				t.Errorf("resultURL=%s", result.ResultURL)
			}
			if tc.trigger == "custom-email-provider" && (result.Notification == nil || result.Notification.Kind != "drop" || result.Notification.Reason != "permanent") {
				t.Errorf("notification=%+v", result.Notification)
			}
		}
	})
	t.Run("dry_run", func(t *testing.T) {
		for i, tc := range cases {
			a := &store.Action{TenantID: "t", ID: fmt.Sprintf("dry%d", i), Name: fmt.Sprintf("dry%d", i), Trigger: tc.trigger, Runtime: actionsrules.Runtime, DraftBuildID: buildID, Code: "exports." + tc.handler + "=async(event,api)=>{" + tc.code + "};"}
			// The reset helper JWT needs continuation state, so dry-run just records
			// redirect and result-URL commands without attempting a continuation.
			if tc.trigger == "password-reset-post-challenge" {
				a.Code = "exports." + tc.handler + `=async(event,api)=>{if(!api.redirect.canRedirect())throw Error('cannot redirect');api.redirect.sendUserTo('https://app.test/');api.transaction.setResultUrl('https://app.test/done');};`
			}
			if err := e.Store.Actions().CreateAction(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			raw, err := e.Test(context.Background(), "t", a.ID, json.RawMessage(`{"request":{}}`))
			if err != nil {
				t.Fatal(err)
			}
			var out testOutput
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatal(err)
			}
			if out.Error != nil || len(out.Commands) == 0 {
				t.Errorf("%s: %s", tc.trigger, raw)
			}
			if record, err := e.Store.Actions().GetExecution(context.Background(), "t", out.ExecutionID); err != store.ErrNotFound || record != nil {
				t.Errorf("dry-run wrote execution=%+v err=%v", record, err)
			}
		}
	})
	t.Run("forged_commands", func(t *testing.T) {
		for _, tc := range []struct{ trigger, op string }{{"post-user-registration", "access.deny"}, {"post-change-password", "user.setUserMetadata"}, {"pre-user-registration", "transaction.clearTargetScopes"}, {"custom-email-provider", "redirect.sendUserTo"}, {"password-reset-post-challenge", "accessToken.setCustomClaim"}, {"unknown", "cache.delete"}} {
			if err := newAccum(tc.trigger, nil, nil, true).apply(command{Op: tc.op}); errorID(err) != "invalid_api_call" {
				t.Errorf("%s %s: %v", tc.trigger, tc.op, err)
			}
		}
	})
}

func triggerTestEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	node, err := exec.Command("node", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := noderunner.CheckNodeVersion(strings.TrimSpace(string(node))); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Actions{CacheDir: t.TempDir(), IdleTimeout: time.Minute}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b, err := build.New(cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	pool, err := NewRunner(cfg, b, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	id, err := b.Queue(ctx, "t", nil, actionsrules.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		v, err := st.Actions().GetBuild(ctx, "t", id)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status == store.BuildBuilt {
			break
		}
		if v.Status == store.BuildFailed || time.Now().After(deadline) {
			t.Fatalf("empty build: %+v", v)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &Engine{Store: st, Builds: b, Runner: pool, Log: log}, id
}

func triggerTestRun(t *testing.T, e *Engine, buildID, trigger, handler, code string) (*accum, *stepOut, error) {
	t.Helper()
	a := newAccum(trigger, nil, nil, true)
	f := &flow{tenantID: "t", trigger: trigger, handler: handler, hostname: "tenant.test", state: "fixture-state", acc: a, cache: newActionCache(), deadline: time.Now().Add(10 * time.Second)}
	out, err := e.step(context.Background(), f, unit{name: "fixture", actionID: t.Name(), versionKey: t.Name() + code, code: "exports." + handler + " = async (event,api) => {" + code + "};", buildID: buildID}, map[string]any{"user": map[string]any{"user_id": "auth0|u"}, "request": map[string]any{}, "transaction": map[string]any{}})
	return a, out, err
}

// Golden JSON expectations are hand-authored; changes that leak credentials,
// invent risk fields or use the wrong trigger profile must fail these tests.
func TestTriggerEvents(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	ten := &store.Tenant{ID: "t", Name: "tenant", CanonicalHost: "tenant.test", FriendlyName: "Example", SupportEmail: "support@example.test", SupportURL: "https://help.test/", PictureURL: "https://img.test/logo"}
	resolved := tenant.Resolved{Tenant: ten, Host: "login.example.test"}
	user := &store.User{UserID: "auth0|u", Email: "u@example.test", EmailVerified: true, Username: "person", Name: "Example User", GivenName: "Example", FamilyName: "User", Nickname: "example", Picture: "https://img.test/u", PhoneNumber: "+123", PhoneVerified: true, CreatedAt: now, UpdatedAt: now, LastPasswordReset: &now, AppMetadata: map[string]any{"plan": "free"}, UserMetadata: map[string]any{"color": "blue"}}
	conn := &store.Connection{ID: "con", Name: "database", Strategy: "auth0"}
	req := RequestInfo{IP: "192.0.2.1", Method: "POST", Language: "de", UserAgent: "test", Body: map[string]any{"password": "SECRET", "password_confirmation": "SECRET", "nested": map[string]any{"newPassword": "SECRET", "client_secret": "SECRET", "keep": "yes"}, "items": []any{map[string]any{"old_password": "SECRET", "keep": true, "pass_word": "SECRET"}}, "custom": "value", "typed": map[string]string{"password": "SECRET", "keep": "typed"}}}
	txn := &TransactionInfo{Locale: "de", Protocol: "oidc-basic-profile", RedirectURI: "https://app.test/cb", RequestedScopes: []string{"openid"}, ResponseMode: "query", ResponseType: "code", State: "state", UILocales: "de en", Prompt: "login", LoginHint: "u@example.test", ACRValues: "urn:example"}
	safeReq := req
	safeReq.Body = map[string]any{"custom": "value"}
	reg := RegistrationInput{Tenant: resolved, Client: &store.Client{ClientID: "app", Name: "App"}, User: user, Connection: conn, Request: req, Transaction: txn, CustomDomain: "login.example.test"}
	a := newAccum("pre-user-registration", nil, nil, false)
	a.eff.UserMetadata = map[string]any{"color": "green"}
	requestJSON := `"request":{"body":{"custom":"value","items":[{"keep":true}],"nested":{"keep":"yes"},"typed":{"keep":"typed"}},"hostname":"login.example.test","ip":"192.0.2.1","language":"de","method":"POST","user_agent":"test"}`
	connJSON := `"connection":{"id":"con","metadata":{},"name":"database","strategy":"auth0"}`
	txnJSON := `"transaction":{"acr_values":"urn:example","locale":"de","login_hint":"u@example.test","prompt":"login","protocol":"oidc-basic-profile","redirect_uri":"https://app.test/cb","requested_scopes":["openid"],"response_mode":"query","response_type":"code","state":"state","ui_locales":"de en"}`
	canonicalUser := `{"app_metadata":{"plan":"free"},"created_at":"2026-10-28T12:00:00Z","email":"u@example.test","email_verified":true,"family_name":"User","given_name":"Example","identities":[],"name":"Example User","nickname":"example","phone_number":"+123","phone_verified":true,"picture":"https://img.test/u","updated_at":"2026-10-28T12:00:00Z","user_id":"auth0|u","user_metadata":{"color":"green"},"username":"person"}`
	cases := []struct {
		name  string
		event map[string]any
		want  string
	}{
		{"post-login", postLoginEvent(&PostLoginInput{Tenant: resolved, Client: reg.Client, User: user, Connection: conn, Request: safeReq, Transaction: *txn, Protocol: txn.Protocol, RequestedScopes: []string{"openid"}}, []string{"member"}, a), `{"authorization":{"roles":["member"]},"client":{"client_id":"app","metadata":{},"name":"App"},` + connJSON + `,"request":{"body":{"custom":"value"},"hostname":"login.example.test","ip":"192.0.2.1","language":"de","method":"POST","query":{},"user_agent":"test"},"stats":{"logins_count":0},"tenant":{"id":"t"},"transaction":{"id":"","locale":"de","metadata":{},"protocol":"oidc-basic-profile","redirect_uri":"https://app.test/cb","requested_scopes":["openid"],"state":"state","target_scopes":[]},"user":` + canonicalUser + `}`},
		{"credentials-exchange", credentialsEvent(&CredentialsInput{Tenant: resolved, Client: reg.Client, Request: safeReq, RequestedScopes: []string{"read"}, TargetScopes: []string{"read"}}, a), `{"accessToken":{"customClaims":{},"scope":["read"]},"client":{"client_id":"app","metadata":{},"name":"App"},"request":{"body":{"custom":"value"},"hostname":"login.example.test","ip":"192.0.2.1","language":"de","method":"POST","user_agent":"test"},"tenant":{"id":"t"},"transaction":{"requested_scopes":["read"],"target_scopes":[]}}`},

		{"pre", registrationEvent(&reg, a), `{"client":{"client_id":"app","metadata":{},"name":"App"},` + connJSON + `,"custom_domain":{"domain":"login.example.test","domain_metadata":{}},` + requestJSON + `,"tenant":{"id":"t"},` + txnJSON + `,"user":{"app_metadata":{"plan":"free"},"email":"u@example.test","family_name":"User","given_name":"Example","name":"Example User","nickname":"example","phone_number":"+123","picture":"https://img.test/u","user_metadata":{"color":"green"},"username":"person"}}`},
		{"post", postRegistrationEvent(&reg, a), `{` + connJSON + `,` + requestJSON + `,"tenant":{"id":"t"},` + txnJSON + `,"user":` + canonicalUser + `}`},
		{"password", postChangePasswordEvent(&PostChangePasswordInput{Tenant: resolved, User: user, Connection: conn, Request: req}), `{` + connJSON + `,` + requestJSON + `,"tenant":{"id":"t"},"user":{"email":"u@example.test","email_verified":true,"last_password_reset":"2026-10-28T12:00:00Z","phone_number":"+123","phone_verified":true,"user_id":"auth0|u","username":"person"}}`},
		{"reset", resetChallengeEvent(&ResetChallengeInput{Tenant: resolved, Client: reg.Client, User: user, Connection: conn, Request: req, Ticket: &store.PasswordResetTicket{Lang: "de"}}, a), `{"client":{"client_id":"app","metadata":{},"name":"App"},` + connJSON + `,` + strings.Replace(requestJSON, `"method":"POST"`, `"method":"POST","query":{}`, 1) + `,"tenant":{"id":"t"},"transaction":{"correlation_id":"","locale":"de"},"user":` + canonicalUser + `}`},
		{"email", emailEvent(&EmailInput{Tenant: "t", TenantInfo: ten, Client: reg.Client, User: user, Connection: conn, Request: req, Message: EmailMessage{From: "sender@test", To: "u@example.test", Subject: "Welcome", HTML: "<p>Hello</p>", Text: "Hello", Locale: "de", Type: "welcome_email"}}, a), `{"client":{"client_id":"app","metadata":{},"name":"App"},` + connJSON + `,"notification":{"from":"sender@test","html":"<p>Hello</p>","locale":"de","message_type":"welcome_email","subject":"Welcome","text":"Hello","to":"u@example.test"},` + strings.Replace(requestJSON, `"hostname":"login.example.test"`, `"hostname":"tenant.test"`, 1) + `,"tenant":{"friendly_name":"Example","id":"t","support_email":"support@example.test","support_url":"https://help.test/"},"user":` + canonicalUser + `}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want any
			if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			got := mustMarshal(t, tc.event)
			var normalized any
			_ = json.Unmarshal([]byte(got), &normalized)
			if !reflect.DeepEqual(normalized, want) {
				t.Errorf("event = %s\nwant = %s", got, tc.want)
			}
			for _, forbidden := range []string{"SECRET", `"geoip"`, `"security_context"`, `"authentication"`} {
				if strings.Contains(got, forbidden) {
					t.Errorf("event leaked %s", forbidden)
				}
			}
		})
	}
	reg.Transaction = nil
	reg.CustomDomain = ""
	event := registrationEvent(&reg, a)
	if _, ok := event["transaction"]; ok {
		t.Error("dbconnections signup has transaction")
	}
	if _, ok := event["custom_domain"]; ok {
		t.Error("canonical signup has custom_domain")
	}
	if user.UserMetadata["color"] != "blue" || !strings.Contains(mustMarshal(t, req.Body), "SECRET") {
		t.Error("event builder mutated its input")
	}
}
