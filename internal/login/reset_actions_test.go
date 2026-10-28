package login

import (
	"bytes"
	"context"
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
		re.bind(t, resetRedirectCode)
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
		if re.ticket(t, ticket).ChallengePassedAt == nil {
			t.Fatal("resumed pass not recorded")
		}
		if replay := b.do(t, "GET", "/continue?"+url.Values{"state": {state}, "ok": {"1"}}.Encode(), nil); !invalidContinue(replay) {
			t.Fatalf("replay = %d %s", replay.Code, replay.Body)
		}
		if rec := submit(t, b, rec, ticket, "new password 123"); rec.Code != 200 || !re.passwordIs(t, "new password 123") {
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
		rec = submit(t, b, rec, ticket, "new password 123")
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

	t.Run("challengeWith fails closed", func(t *testing.T) {
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
