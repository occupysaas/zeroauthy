package login

import (
	"bytes"
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type resetActionsEnv struct {
	*env
	a  *actionstest.Env
	tn *store.Tenant
	n  int
}

// newResetActionsEnv serves the reset pages and /continue with a real engine.
func newResetActionsEnv(t *testing.T) *resetActionsEnv {
	t.Helper()
	e := newEnv(t)
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	a := actionstest.NewOffline(t, e.st, w)
	a.Engine.Now = fixedNow
	e.h.Actions = a.Engine
	e.h.Authz.Actions = a.Engine
	e.h.Authz.ResetContinue = e.h.ResetContinue
	cont := tenant.NewResolver(e.st.Tenants(), "", false).Middleware(http.HandlerFunc(e.h.Authz.Continue))
	pages := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/continue" {
			cont.ServeHTTP(w, r)
			return
		}
		pages.ServeHTTP(w, r)
	})
	return &resetActionsEnv{env: e, a: a, tn: mustTenant(t, e, "acme")}
}

// bind replaces the reset trigger's bindings with one Action running code.
func (re *resetActionsEnv) bind(t *testing.T, code string) {
	t.Helper()
	re.n++
	name := "reset" + string(rune('a'+re.n))
	re.a.Bind(t, re.tn.ID, actions.TriggerResetPostChallenge, re.a.Deploy(t, re.tn.ID, actions.TriggerResetPostChallenge, name, code))
}

func (re *resetActionsEnv) ticket(t *testing.T, raw string) *store.PasswordResetTicket {
	t.Helper()
	tk, err := re.st.PasswordResetTickets().GetByTokenHash(context.Background(), re.tn.ID, secrets.HashToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (re *resetActionsEnv) passwordIs(t *testing.T, pw string) bool {
	t.Helper()
	_, err := re.h.Database.Login(context.Background(), re.conn(t), "alice@acme.test", pw)
	return err == nil
}

// submit posts the new-password form rendered in rec.
func submit(t *testing.T, b *browser, rec *httptest.ResponseRecorder, ticket, pw string) *httptest.ResponseRecorder {
	t.Helper()
	m := csrfField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no reset form: %d %s", rec.Code, rec.Body)
	}
	return b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {ticket}, "csrf": {m[1]}, "password": {pw}, "password_confirm": {pw}})
}

// redirectState opens ticket in b and returns the continue state of the
// Action's redirect.
func redirectState(t *testing.T, b *browser, ticket string) string {
	t.Helper()
	rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.Host != "ext.example.test" || loc.Query().Get("state") == "" || loc.Query().Get("ticket") != "" {
		t.Fatalf("redirect = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	return loc.Query().Get("state")
}

const resetRedirectCode = `exports.onExecutePostChallenge=(event,api)=>{api.redirect.sendUserTo('https://ext.example.test/verify',{query:{who:event.user.email}});};
exports.onContinuePostChallenge=(event,api)=>{if(event.request.query.ok!=='1')api.access.deny('verification failed');};`

func invalidContinue(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "invalid_request")
}

func TestResetPostChallenge(t *testing.T) {
	t.Run("pass recorded once", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, `exports.onExecutePostChallenge=(event,api)=>{if(event.user.email!=='alice@acme.test'||event.transaction.locale!=='en'||event.request.query.ticket!==undefined)throw Error('bad event');};`)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		rec := re.browser("acme.example.test").do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if rec.Code != 200 || !csrfField.MatchString(rec.Body.String()) {
			t.Fatalf("form = %d %s", rec.Code, rec.Body)
		}
		if tk := re.ticket(t, ticket); tk.ChallengePassedAt == nil || tk.UsedAt != nil {
			t.Fatalf("ticket after pass = %+v", tk)
		}
		// A recorded pass skips the flow for any browser.
		re.bind(t, `exports.onExecutePostChallenge=(event,api)=>api.access.deny('must not run');`)
		b2 := re.browser("acme.example.test")
		rec = b2.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "must not run") {
			t.Fatalf("second browser = %d %s", rec.Code, rec.Body)
		}
		if rec := submit(t, b2, rec, ticket, "new password 123"); rec.Code != 200 || !re.passwordIs(t, "new password 123") {
			t.Fatalf("submit = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("deny", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, `exports.onExecutePostChallenge=(event,api)=>api.access.deny('Resets are paused for <b>you</b>');`)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		b := re.browser("acme.example.test")
		rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "Resets are paused for &lt;b&gt;you&lt;/b&gt;") || csrfField.MatchString(rec.Body.String()) {
			t.Fatalf("deny = %d %s", rec.Code, rec.Body)
		}
		if tk := re.ticket(t, ticket); tk.ChallengePassedAt != nil || tk.UsedAt != nil {
			t.Fatalf("denied ticket = %+v", tk)
		}
		// Reopening runs the flow again.
		re.bind(t, `exports.onExecutePostChallenge=()=>{};`)
		rec = b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if rec.Code != 200 || re.ticket(t, ticket).ChallengePassedAt == nil {
			t.Fatalf("reopen = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("redirect and continue", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, resetRedirectCode+`exports.onContinuePostChallenge=(event,api)=>{if(event.request.query.ok!=='1')return api.access.deny('verification failed');api.transaction.setResultUrl('https://app.acme.test/done');};`)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		b := re.browser("acme.example.test")
		state := redirectState(t, b, ticket)
		if re.ticket(t, ticket).ChallengePassedAt != nil {
			t.Fatal("pass recorded before the flow resumed")
		}
		rec := b.do(t, "GET", "/continue?"+url.Values{"state": {state}, "ok": {"1"}}.Encode(), nil)
		if rec.Code != 200 || !csrfField.MatchString(rec.Body.String()) || !strings.Contains(rec.Body.String(), ticket) {
			t.Fatalf("continue = %d %s", rec.Code, rec.Body)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://app.acme.test;") {
			t.Fatalf("continued reset form CSP omits validated result origin: %s", csp)
		}
		if re.ticket(t, ticket).ChallengePassedAt == nil {
			t.Fatal("resumed pass not recorded")
		}
		if replay := b.do(t, "GET", "/continue?"+url.Values{"state": {state}, "ok": {"1"}}.Encode(), nil); !invalidContinue(replay) {
			t.Fatalf("replay = %d %s", replay.Code, replay.Body)
		}
		if rec := submit(t, b, rec, ticket, "new password 123"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.acme.test/done" || !re.passwordIs(t, "new password 123") {
			t.Fatalf("submit = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("continue deny", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, resetRedirectCode)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		b := re.browser("acme.example.test")
		state := redirectState(t, b, ticket)
		rec := b.do(t, "GET", "/continue?state="+url.QueryEscape(state), nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "verification failed") {
			t.Fatalf("continue deny = %d %s", rec.Code, rec.Body)
		}
		if tk := re.ticket(t, ticket); tk.ChallengePassedAt != nil || tk.UsedAt != nil {
			t.Fatalf("ticket = %+v", tk)
		}
	})

	t.Run("continue binding", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, resetRedirectCode)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		b := re.browser("acme.example.test")
		state := redirectState(t, b, ticket)
		q := "/continue?" + url.Values{"state": {state}, "ok": {"1"}}.Encode()
		// No reset cookies at all.
		if rec := re.browser("acme.example.test").do(t, "GET", q, nil); !invalidContinue(rec) {
			t.Fatalf("no cookie = %d %s", rec.Code, rec.Body)
		}
		// Another browser's page cookie for the same ticket.
		other := re.browser("acme.example.test")
		redirectState(t, other, ticket)
		if rec := other.do(t, "GET", q, nil); !invalidContinue(rec) {
			t.Fatalf("other cookie = %d %s", rec.Code, rec.Body)
		}
		// The same page cookie claiming another ticket.
		second := re.issueTicket(t, "alice@acme.test", time.Hour)
		forged := re.browser("acme.example.test")
		for name, c := range b.cookies {
			cc := *c
			forged.cookies[name] = &cc
		}
		c := forged.cookies[resetContinueCookie]
		if c == nil {
			t.Fatalf("no %s cookie in %v", resetContinueCookie, b.cookies)
		}
		_, page, _ := strings.Cut(c.Value, ".")
		c.Value = second + "." + page
		if rec := forged.do(t, "GET", q, nil); !invalidContinue(rec) {
			t.Fatalf("other ticket = %d %s", rec.Code, rec.Body)
		}
		for _, raw := range []string{ticket, second} {
			if tk := re.ticket(t, raw); tk.ChallengePassedAt != nil || tk.UsedAt != nil {
				t.Fatalf("ticket = %+v", tk)
			}
		}
	})

	t.Run("result url", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, `exports.onExecutePostChallenge=(event,api)=>api.transaction.setResultUrl('https://app.acme.test/done',{query:{from:'reset'}});`)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		b := re.browser("acme.example.test")
		rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://app.acme.test;") {
			t.Fatalf("reset form CSP omits validated result origin: %s", csp)
		}
		invalid := submit(t, b, rec, ticket, "short")
		if csp := invalid.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://app.acme.test;") {
			t.Fatalf("invalid password form CSP loses result origin: %s", csp)
		}
		rec = submit(t, b, invalid, ticket, "new password 123")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://app.acme.test/done?from=reset" {
			t.Fatalf("result = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
	})

	t.Run("invalid result url fails closed", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, `exports.onExecutePostChallenge=(event,api)=>api.transaction.setResultUrl('http://app.acme.test/done');`)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		rec := re.browser("acme.example.test").do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "exe_") || csrfField.MatchString(rec.Body.String()) {
			t.Fatalf("invalid url = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("challengeWith requires tenant flag", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.bind(t, `exports.onExecutePostChallenge=(event,api)=>{try{api.authentication.challengeWith({type:'otp'});}catch(e){}};`)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		rec := re.browser("acme.example.test").do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "exe_") || csrfField.MatchString(rec.Body.String()) {
			t.Fatalf("challengeWith = %d %s", rec.Code, rec.Body)
		}
		if tk := re.ticket(t, ticket); tk.ChallengePassedAt != nil || tk.UsedAt != nil {
			t.Fatalf("ticket = %+v", tk)
		}
	})

	t.Run("post without pass", func(t *testing.T) {
		re := newResetActionsEnv(t)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		b := re.browser("acme.example.test")
		// The page loads before any binding exists.
		form := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
		re.bind(t, `exports.onExecutePostChallenge=()=>{};`)
		rec := submit(t, b, form, ticket, "new password 123")
		if rec.Code != 400 || strings.Contains(rec.Body.String(), "Password changed") {
			t.Fatalf("unpassed submit = %d %s", rec.Code, rec.Body)
		}
		if tk := re.ticket(t, ticket); tk.UsedAt != nil || tk.ChallengePassedAt != nil {
			t.Fatalf("ticket = %+v", tk)
		}
		if !re.passwordIs(t, "alice password 1") {
			t.Fatal("password changed without a pass")
		}
		// Opening the link again runs the challenge, then the submit works.
		if rec := completeReset(t, b, ticket, "new password 123"); rec.Code != 200 || !re.passwordIs(t, "new password 123") {
			t.Fatalf("after pass = %d %s", rec.Code, rec.Body)
		}
	})

	t.Run("no bindings", func(t *testing.T) {
		re := newResetActionsEnv(t)
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		rec := completeReset(t, re.browser("acme.example.test"), ticket, "new password 123")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") {
			t.Fatalf("reset = %d %s", rec.Code, rec.Body)
		}
		if re.ticket(t, ticket).ChallengePassedAt != nil {
			t.Fatal("pass recorded without bindings")
		}
	})
}

func (re *resetActionsEnv) jobs(t *testing.T) []store.ActionJob {
	t.Helper()
	jobs, err := re.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

func TestPostChangePassword(t *testing.T) {
	t.Run("reset submit", func(t *testing.T) {
		re := newResetActionsEnv(t)
		re.a.Bind(t, re.tn.ID, actions.TriggerPostChangePassword, re.a.Deploy(t, re.tn.ID, actions.TriggerPostChangePassword, "pcp",
			`exports.onExecutePostChangePassword=(event)=>{throw Error('post-change '+event.user.email+' '+event.user.last_password_reset);};`))
		ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
		if rec := completeReset(t, re.browser("acme.example.test"), ticket, "new password 123"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") {
			t.Fatalf("reset = %d %s", rec.Code, rec.Body)
		}
		if u := re.user(t, "alice@acme.test"); u.LastPasswordReset == nil || !u.LastPasswordReset.Equal(fixedNow()) {
			t.Fatalf("last_password_reset = %v", u.LastPasswordReset)
		}
		jobs := re.jobs(t)
		if len(jobs) != 1 || jobs[0].Trigger != actions.TriggerPostChangePassword {
			t.Fatalf("jobs = %+v", jobs)
		}
		// The failing Action only leaves a failed job behind.
		if got := re.a.Engine.RunJob(context.Background(), &jobs[0]); got == nil || got.Status != "failed" || len(got.ExecutionIDs) != 1 {
			t.Fatalf("job = %+v", got)
		}
		if !strings.Contains(re.a.Logs.String(), "post-change alice@acme.test 20") {
			t.Fatalf("event logs = %s", re.a.Logs)
		}
	})

	t.Run("legacy not changed", func(t *testing.T) {
		le := newLegacyResetEnv(t)
		le.changed = false
		w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
		a := actionstest.NewOffline(t, le.st, w)
		le.h.Actions = a.Engine
		tn := mustTenant(t, le.env, "acme")
		a.Bind(t, tn.ID, actions.TriggerPostChangePassword, a.Deploy(t, tn.ID, actions.TriggerPostChangePassword, "pcp", `exports.onExecutePostChangePassword=()=>{};`))
		b := le.browser("acme.example.test")
		ticket := le.requestLegacyReset(t, b)
		if rec := completeReset(t, b, ticket, "new legacy pw 1"); rec.Code != 400 {
			t.Fatalf("not changed = %d %s", rec.Code, rec.Body)
		}
		jobs, err := le.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
		if err != nil || len(jobs) != 0 {
			t.Fatalf("jobs = %+v %v", jobs, err)
		}
		if u, err := le.st.Users().Get(context.Background(), tn.ID, "auth0|42"); err != nil || u.LastPasswordReset != nil {
			t.Fatalf("user = %+v %v", u, err)
		}
		// A change the script accepts does queue one.
		le.changed = true
		ticket = le.requestLegacyReset(t, b)
		if rec := completeReset(t, b, ticket, "new legacy pw 2"); rec.Code != 200 {
			t.Fatalf("changed = %d %s", rec.Code, rec.Body)
		}
		if jobs, err := le.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10); err != nil || len(jobs) != 1 {
			t.Fatalf("jobs = %+v %v", jobs, err)
		}
	})
}

// Inject only the enqueue failure; the real memory transaction must still
// commit or roll back the password and profile writes as a unit.
type resetJobFailureStore struct {
	store.Store
	err error
}

func (s resetJobFailureStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(resetJobFailureStore{tx, s.err}) })
}
func (s resetJobFailureStore) Actions() store.Actions {
	return resetJobFailureActions{s.Store.Actions(), s.err}
}

type resetJobFailureActions struct {
	store.Actions
	err error
}

func (s resetJobFailureActions) EnqueueJob(context.Context, *store.ActionJob) error { return s.err }

// Moving enqueue outside the password transaction would leave the new password
// and timestamp committed when queue storage fails. Treating cap overflow as
// a general storage failure would instead reject a valid password change.
func TestPostChangePasswordQueueFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		changed bool
	}{
		{"storage failure rolls back", errors.New("queue storage failed"), 500, false},
		{"queue full preserves reset", store.ErrPrecondition, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			re := newResetActionsEnv(t)
			re.a.Bind(t, re.tn.ID, actions.TriggerPostChangePassword, re.a.Deploy(t, re.tn.ID, actions.TriggerPostChangePassword, "pcp", `exports.onExecutePostChangePassword=()=>{};`))
			ticket := re.issueTicket(t, "alice@acme.test", time.Hour)
			re.h.Store = resetJobFailureStore{re.st, tc.err}
			rec := completeReset(t, re.browser("acme.example.test"), ticket, "new password 123")
			if rec.Code != tc.status {
				t.Fatalf("reset = %d %s", rec.Code, rec.Body)
			}
			if re.passwordIs(t, "new password 123") != tc.changed {
				t.Fatal("unexpected password change")
			}
			u := re.user(t, "alice@acme.test")
			if (u.LastPasswordReset != nil) != tc.changed {
				t.Fatalf("last_password_reset = %v", u.LastPasswordReset)
			}
			if !tc.changed && !re.passwordIs(t, "alice password 1") {
				t.Fatal("original password not preserved")
			}
			if !tc.changed && re.ticket(t, ticket).UsedAt == nil {
				t.Fatal("failed reset restored an already consumed ticket")
			}
			if tc.changed && !strings.Contains(re.a.Logs.String(), "post-change-password Action job dropped") {
				t.Fatal("full queue drop was not logged")
			}
			if jobs := re.jobs(t); len(jobs) != 0 {
				t.Fatalf("unexpected jobs %+v", jobs)
			}
		})
	}
}

func TestResetPostChallengeChallengeWith(t *testing.T) {
	for _, call := range []string{`challengeWith({type:'otp'})`, `challengeWithAny([{type:'otp'}])`, `challengeWithAny([{type:'otp'},{type:'email'}])`} {
		t.Run(call, func(t *testing.T) {
			f := newMFAFixture(t)
			f.policy(t, "otp", "email")
			secret := f.enrolled(t, "otp", false)
			f.enrolled(t, "email", false)
			ctx := context.Background()
			tn, _ := f.st.Tenants().Get(ctx, f.tn.ID)
			tn.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
			if err := f.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
			f.h.Actions = a.Engine
			a.Bind(t, tn.ID, actions.TriggerResetPostChallenge, a.Deploy(t, tn.ID, actions.TriggerResetPostChallenge, "reset-mfa", `exports.onExecutePostChallenge=(event,api)=>{api.authentication.`+call+`;api.transaction.setResultUrl('https://app.acme.test/done');};`))
			var existing *store.LoginSession
			if strings.Contains(call, "Any") {
				rr := httptest.NewRequest("GET", "https://acme.example.test/", nil)
				rr = rr.WithContext(tenant.WithResolved(ctx, tenant.Resolved{Tenant: tn, Host: "acme.example.test"}))
				ww := httptest.NewRecorder()
				var err error
				existing, err = f.h.Sessions.Start(ctx, ww, rr, tn, f.uid, "Username-Password-Authentication", *f.clock)
				if err != nil {
					t.Fatal(err)
				}
				for _, c := range ww.Result().Cookies() {
					f.b.cookies[c.Name] = c
				}
				*f.clock = f.clock.Add(time.Minute)
			}
			raw := f.issueTicket(t, aliceLogin, time.Hour)
			rec := f.b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != 303 || loc.Path != "/u/mfa" {
				t.Fatalf("MFA not required: %d %s %s", rec.Code, loc, rec.Body)
			}
			f.state = loc.Query().Get("state")
			tk, _ := f.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(raw))
			if tk.ChallengePassedAt != nil || tk.UsedAt != nil {
				t.Fatal("reset passed before proof")
			}
			page := f.page(t, "/u/mfa")
			if strings.Contains(call, "email") {
				if !strings.Contains(page.Body.String(), `name="factor"`) {
					t.Fatalf("challengeWithAny did not show factor selector")
				}
				choice := f.post(t, "/u/mfa", url.Values{"factor": {"otp"}})
				if choice.Code != 303 {
					t.Fatalf("choose factor %d", choice.Code)
				}
				f.page(t, "/u/mfa-otp-challenge")
			}
			bad := f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {"000000"}})
			if bad.Code != 400 {
				t.Fatalf("bad proof %d", bad.Code)
			}
			f.page(t, "/u/mfa-otp-challenge")
			proof := f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
			loc, _ = url.Parse(proof.Header().Get("Location"))
			if proof.Code != 303 || loc.Path != "/u/reset-password" {
				t.Fatalf("proof %d %s %s", proof.Code, loc, proof.Body)
			}
			tk, _ = f.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(raw))
			if tk.ChallengePassedAt == nil || tk.UsedAt != nil {
				t.Fatalf("ticket=%+v", tk)
			}
			for _, c := range proof.Result().Cookies() {
				if c.Name == "za_session" {
					t.Fatal("reset proof established SSO")
				}
			}
			req := httptest.NewRequest("GET", "https://acme.example.test/", nil)
			for _, c := range f.b.cookies {
				req.AddCookie(c)
			}
			sess, err := f.h.Sessions.Lookup(ctx, req, tn)
			if err != nil || existing == nil && sess != nil {
				t.Fatalf("reset proof logged in: %+v %v", sess, err)
			}
			if existing != nil && (sess == nil || sess.ID != existing.ID || !sess.MFAAt.IsZero() || !sess.LastInteractedAt.Equal(existing.LastInteractedAt)) {
				t.Fatalf("reset proof changed existing SSO: before=%+v after=%+v", existing, sess)
			}
			page = f.b.do(t, "GET", loc.RequestURI(), nil)
			done := submit(t, f.b, page, raw, "new password 123")
			if done.Code != 302 || done.Header().Get("Location") != "https://app.acme.test/done" {
				t.Fatalf("reset %d %s", done.Code, done.Body)
			}
		})
	}
}

// All changes occur after reset authority is issued. None may turn that
// proof-only authority into a reset pass, SSO session, or new enrollment.
func TestResetPostChallengeChallengeWithBoundaries(t *testing.T) {
	for _, change := range []string{"password", "epoch", "email", "blocked", "expired", "used", "cookie", "browser", "no-factor"} {
		t.Run(change, func(t *testing.T) {
			f := newMFAFixture(t)
			f.policy(t, "otp")
			secret := f.enrolled(t, "otp", false)
			ctx := context.Background()
			tn, _ := f.st.Tenants().Get(ctx, f.tn.ID)
			tn.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
			if err := f.st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
			f.h.Actions = a.Engine
			a.Bind(t, tn.ID, actions.TriggerResetPostChallenge, a.Deploy(t, tn.ID, actions.TriggerResetPostChallenge, "bound-reset-mfa", `exports.onExecutePostChallenge=(event,api)=>api.authentication.challengeWith({type:'otp'});`))
			if change == "no-factor" {
				if err := f.st.MFA().DeleteUserAuthenticators(ctx, tn.ID, f.uid, nil); err != nil {
					t.Fatal(err)
				}
			}
			raw := f.issueTicket(t, aliceLogin, time.Hour)
			rec := f.b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if change == "no-factor" {
				if rec.Code != 400 {
					t.Fatalf("reset enrolled instead of requiring proof %d", rec.Code)
				}
				aa, _ := f.st.MFA().ListAuthenticators(ctx, tn.ID, f.uid)
				if len(aa) != 0 {
					t.Fatal("reset created authenticator")
				}
				return
			}
			if rec.Code != 303 {
				t.Fatalf("start %d %s", rec.Code, rec.Body)
			}
			f.state = loc.Query().Get("state")
			f.page(t, "/u/mfa")
			// A direct password form submit cannot skip proof, even with the reset CSRF.
			direct := f.b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {raw}, "csrf": {f.b.cookies[resetCookie].Value}, "password": {"new password 123"}, "password_confirm": {"new password 123"}})
			if direct.Code != 400 {
				t.Fatalf("direct bypass %d", direct.Code)
			}
			u, _ := f.st.Users().Get(ctx, tn.ID, f.uid)
			switch change {
			case "password":
				_, _ = f.st.Users().BumpVersion(ctx, tn.ID, f.uid)
			case "epoch":
				_ = f.st.MFA().BumpRememberEpoch(ctx, tn.ID, f.uid)
			case "email":
				u.Email = "changed@example.test"
				_ = f.st.Users().Update(ctx, u)
			case "blocked":
				u.Blocked = true
				_ = f.st.Users().Update(ctx, u)
			case "expired":
				*f.clock = f.clock.Add(2 * time.Hour)
			case "used":
				_, _ = f.st.PasswordResetTickets().Consume(ctx, tn.ID, secrets.HashToken(raw), *f.clock)
			case "cookie":
				f.b.cookies[resetCookie].Value = "other-page"
			case "browser":
				f.b = f.browser(f.b.host)
			}
			proof := f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
			if proof.Code == 200 || strings.Contains(proof.Header().Get("Location"), "/u/reset-password?ticket=") {
				t.Fatalf("stale authority accepted %d %s", proof.Code, proof.Header().Get("Location"))
			}
			tk, _ := f.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(raw))
			if tk.ChallengePassedAt != nil {
				t.Fatal("stale authority passed ticket")
			}
		})
	}
}

func TestResetPostChallengeMFACookieIngressPrivacy(t *testing.T) {
	f := newMFAFixture(t)
	bearer := "reset-cookie-bearer-must-be-masked"
	output := &syncBuffer{}
	logger := slog.New(logscrub.Handler(slog.NewJSONHandler(output, nil)))
	handler := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.h.MFAPage(w, r)
		// Probe the real sink at the rejected request boundary; no production
		// event is emitted for an invalid hosted transaction.
		logger.InfoContext(r.Context(), "rejected MFA page boundary", "user_agent", r.UserAgent())
	}))
	req := httptest.NewRequest("GET", "https://acme.example.test/u/mfa?state=invalid", nil)
	req.AddCookie(&http.Cookie{Name: "za_reset_mfa", Value: bearer})
	req.Header.Set("User-Agent", "client "+bearer)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(output.String(), bearer) || !strings.Contains(output.String(), "client ") {
		t.Fatalf("MFA ingress leaked bearer %s", output.String())
	}
}

func TestResetPostChallengeChallengeWithRedirect(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", false)
	ctx := context.Background()
	tn, _ := f.st.Tenants().Get(ctx, f.tn.ID)
	tn.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
	f.h.Actions = a.Engine
	f.h.Authz.Actions = a.Engine
	f.h.Authz.ResetContinue = f.h.ResetContinue
	a.Bind(t, tn.ID, actions.TriggerResetPostChallenge, a.Deploy(t, tn.ID, actions.TriggerResetPostChallenge, "reset-mfa-redirect", `exports.onExecutePostChallenge=(event,api)=>{api.authentication.challengeWith({type:'otp'});api.redirect.sendUserTo('https://ext.example.test/');};exports.onContinuePostChallenge=(event,api)=>api.transaction.setResultUrl('https://app.acme.test/done');`))
	old := f.srv
	cont := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.Authz.Continue))
	f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/continue" {
			cont.ServeHTTP(w, r)
		} else {
			old.ServeHTTP(w, r)
		}
	})
	raw := f.issueTicket(t, aliceLogin, time.Hour)
	state := redirectState(t, f.b, raw)
	rec := f.b.do(t, "GET", "/continue?state="+state, nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 303 || loc.Path != "/u/mfa" {
		t.Fatalf("redirect lost MFA effect %d %s", rec.Code, loc)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if rec.Code != 303 || loc.Path != "/u/reset-password" {
		t.Fatalf("proof %d %s", rec.Code, loc)
	}
	tk, _ := f.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(raw))
	if tk.ChallengePassedAt == nil || tk.UsedAt != nil || tk.ChallengeResultURL != "https://app.acme.test/done" {
		t.Fatalf("redirect result not preserved: %+v", tk)
	}
}
