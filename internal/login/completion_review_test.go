package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/oidc"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func reviewLogin(t *testing.T, f *mfaFixture, args ...string) *httptest.ResponseRecorder {
	t.Helper()
	_, state, csrf := f.b.begin(t, args...)
	return f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}})
}
func reviewMFA(t *testing.T, f *mfaFixture, rec *httptest.ResponseRecorder, secret string, remember bool) *httptest.ResponseRecorder {
	t.Helper()
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("MFA missing: %s %s", loc, rec.Body)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa")
	if remember {
		f.setRemember(t, true)
	}
	form := url.Values{"code": {otpAt(secret, *f.clock)}}
	if remember {
		form.Set("remember", "yes")
	}
	return f.post(t, "/u/mfa-otp-challenge", form)
}
func reviewConsent(t *testing.T, f *mfaFixture, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/consent" {
		t.Fatalf("consent missing: %s %s", loc, rec.Body)
	}
	page := f.b.do(t, "GET", loc.RequestURI(), nil)
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("consent page: %d %s", page.Code, page.Body)
	}
	return url.Values{"state": {loc.Query().Get("state")}, "csrf": {m[1]}, "action": {"accept"}}
}

var reviewConsentArgs = []string{"client_id", "partner", "redirect_uri", "https://partner.example/cb", "audience", "https://api.acme.test", "scope", "read:things"}

func TestPendingConsentLogoutRevokesAuthority(t *testing.T) {
	for _, path := range []string{"/v2/logout", "/oidc/logout"} {
		for _, existing := range []bool{false, true} {
			t.Run(path+"/"+map[bool]string{false: "fresh", true: "existing-SSO"}[existing], func(t *testing.T) {
				f := newMFAFixture(t)
				if existing {
					appCode(t, reviewLogin(t, f))
				}
				f.policy(t, "otp")
				secret := f.enrolled(t, "otp", true)
				rec := reviewMFA(t, f, reviewLogin(t, f, append(reviewConsentArgs, "prompt", "login")...), secret, false)
				form := reviewConsent(t, f, rec)
				old := f.srv
				logout := &oidc.Handlers{Store: f.st, Sessions: f.h.Sessions, Now: f.h.Now}
				f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == path {
						handler := logout.Logout
						if path == "/oidc/logout" {
							handler = logout.OidcLogout
						}
						tenantHandler(handler, f.st).ServeHTTP(w, r)
						return
					}
					old.ServeHTTP(w, r)
				})
				// Keep the stale cookies to ensure logout revokes server authority too.
				stale := map[string]*http.Cookie{}
				for k, v := range f.b.cookies {
					stale[k] = v
				}
				target := path
				if path == "/oidc/logout" && existing {
					rows, _ := f.st.Sessions().ListByUser(context.Background(), f.tn.ID, f.uid)
					target += "?logout_hint=" + rows[0].ID
				}
				out := f.b.do(t, "GET", target, nil)
				if out.Code >= 400 {
					t.Fatal(out.Code, out.Body)
				}
				f.b.cookies = stale
				out = f.b.do(t, "POST", "/u/consent", form)
				loc, _ := url.Parse(out.Header().Get("Location"))
				if loc.Query().Get("code") != "" {
					t.Fatal("logged-out consent issued code")
				}
				rows, _ := f.st.Sessions().ListByUser(context.Background(), f.tn.ID, f.uid)
				if len(rows) != 0 {
					t.Fatal("logout continuation created session")
				}
			})
		}
	}
}

func TestConcurrentPendingFlowsAndSSO(t *testing.T) {
	t.Run("two-pending", func(t *testing.T) {
		f := newMFAFixture(t)
		f.policy(t, "otp")
		secret := f.enrolled(t, "otp", true)
		first := reviewLogin(t, f)
		second := reviewLogin(t, f)
		appCode(t, reviewMFA(t, f, first, secret, false))
		*f.clock = f.clock.Add(31 * time.Second)
		appCode(t, reviewMFA(t, f, second, secret, false))
		u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
		if u.LoginsCount != 2 {
			t.Fatal(u.LoginsCount)
		}
	})
	t.Run("SSO-consent", func(t *testing.T) {
		f := newMFAFixture(t)
		appCode(t, reviewLogin(t, f))
		f.policy(t, "otp")
		secret := f.enrolled(t, "otp", true)
		pending := reviewLogin(t, f, "prompt", "login")
		_ = pending
		// Authorize from the retained SSO, not the unrelated pending identity.
		q := url.Values{"client_id": {"partner"}, "redirect_uri": {"https://partner.example/cb"}, "response_type": {"code"}, "audience": {"https://api.acme.test"}, "scope": {"read:things"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		rec := f.b.do(t, "GET", "/authorize?"+q.Encode(), nil)
		rec = reviewMFA(t, f, rec, secret, false)
		form := reviewConsent(t, f, rec)
		reviewCode(t, f.b.do(t, "POST", "/u/consent", form))
	})
}

type browserWrites struct {
	store.Store
	hashes *[]string
}
type captureBrowsers struct {
	store.MFA
	hashes *[]string
}

func (s browserWrites) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(browserWrites{tx, s.hashes}) })
}
func (s browserWrites) MFA() store.MFA { return captureBrowsers{s.Store.MFA(), s.hashes} }
func (s captureBrowsers) PutBrowser(ctx context.Context, b *store.MFABrowser) error {
	*s.hashes = append(*s.hashes, b.Hash)
	return s.MFA.PutBrowser(ctx, b)
}
func TestRememberBrowserCommitsWithAuthorization(t *testing.T) {
	for _, outcome := range []string{"failure", "decline", "accept"} {
		t.Run(outcome, func(t *testing.T) {
			f := newMFAFixture(t)
			f.policy(t, "otp")
			secret := f.enrolled(t, "otp", true)
			var hashes []string
			wrapped := browserWrites{f.st, &hashes}
			f.h.Sessions.Store = wrapped
			f.h.Authz.Store = wrapped
			rec := reviewMFA(t, f, reviewLogin(t, f, reviewConsentArgs...), secret, true)
			form := reviewConsent(t, f, rec)
			if f.b.cookies[session.MFARememberCookie] != nil || len(hashes) != 0 {
				t.Error("remember authority persisted before consent")
			}
			if outcome == "failure" {
				f.h.Authz.Store = codeCommitFailure{wrapped}
			}
			if outcome == "decline" {
				form.Set("action", "decline")
			}
			rec = f.b.do(t, "POST", "/u/consent", form)
			if outcome == "accept" {
				reviewCode(t, rec)
				if f.b.cookies[session.MFARememberCookie] == nil {
					t.Fatal("remember missing on success")
				}
				return
			}
			if f.b.cookies[session.MFARememberCookie] != nil {
				t.Error("remember cookie survived failed completion")
			}
			for _, hash := range hashes {
				if _, err := f.st.MFA().GetBrowser(context.Background(), f.tn.ID, hash, *f.clock); err == nil {
					t.Error("remember row survived failed completion")
				}
			}
		})
	}
}
func TestSlowPendingSessionLifetimeStartsAtCompletion(t *testing.T) {
	f := newMFAFixture(t)
	f.tn.SessionLifetime = 60
	f.tn.IdleSessionLifetime = 60
	if err := f.st.Tenants().Update(context.Background(), f.tn); err != nil {
		t.Fatal(err)
	}
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	firstAt := *f.clock
	rec := reviewLogin(t, f)
	*f.clock = f.clock.Add(2 * time.Minute)
	appCode(t, reviewMFA(t, f, rec, secret, false))
	rows, _ := f.st.Sessions().ListByUser(context.Background(), f.tn.ID, f.uid)
	if len(rows) != 1 || !rows[0].ExpiresAt.After(*f.clock) || !rows[0].IdleExpiresAt.After(*f.clock) || !rows[0].AuthenticatedAt.Equal(firstAt) {
		t.Fatalf("invalid completed session: %+v", rows)
	}
}
func reviewInvitation(t *testing.T, f *mfaFixture, client, email string) []string {
	t.Helper()
	org, conn, u := organizationFixture(t, f.env, store.OrgBehaviorNoPrompt, true, false)
	if email == "" {
		email = u.Email
	}
	if client == "partner" {
		c, _ := f.st.Clients().Get(context.Background(), f.tn.ID, client)
		c.OrganizationUsage = store.OrgUsageAllow
		_ = f.st.Clients().Update(context.Background(), c)
	}
	inv := &store.OrganizationInvitation{TenantID: f.tn.ID, OrganizationID: org.ID, ID: "invite", ClientID: client, InviteeEmail: email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour), AppMetadata: map[string]any{"remove": "invited", "keep": "invited"}, UserMetadata: map[string]any{"remove": "invited"}}
	if err := f.st.OrganizationsII().CreateInvitation(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	return []string{"organization", org.ID, "invitation", "bearer"}
}
func reviewAction(t *testing.T, f *mfaFixture, code string) {
	t.Helper()
	a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
	a.PostLogin(t, f.tn.ID, "review", code)
	f.h.Authz.Actions = a.Engine
	old := f.srv
	f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/continue" {
			tenantHandler(f.h.Authz.Continue, f.st).ServeHTTP(w, r)
			return
		}
		old.ServeHTTP(w, r)
	})
}
func TestInvitationPreviewEmailBeforeActions(t *testing.T) {
	f := newMFAFixture(t)
	args := reviewInvitation(t, f, "spa", "\u017f@example.test")
	u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	u.Email = "s@example.test"
	u.EmailVerified = true
	if err := f.st.Users().Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('ran',true);a.redirect.sendUserTo('https://step.example/')}`)
	_, state, csrf := f.b.begin(t, args...)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {u.Email}, "password": {"alice password 1"}})
	if strings.Contains(rec.Header().Get("Location"), "step.example") {
		t.Fatal("Action saw mismatched invitation identity")
	}
	saved, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	if saved.AppMetadata["ran"] != nil {
		t.Fatal("Action ran for mismatched invitation")
	}
}
func TestInvitationActionDeletionSurvivesCompletion(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "otp")
	secret := f.enrolled(t, "otp", true)
	args := append(reviewInvitation(t, f, "partner", ""), reviewConsentArgs...)
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>{if(e.user.app_metadata.remove!=='invited')throw Error('missing preview');a.user.setAppMetadata('remove',null);a.user.setUserMetadata('remove',null);a.redirect.sendUserTo('https://step.example/')};exports.onContinuePostLogin=(e,a)=>{a.user.setAppMetadata('other','value')}`)
	rec := reviewLogin(t, f, args...)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "step.example" {
		t.Fatal(loc, rec.Body)
	}
	rec = f.b.do(t, "GET", "/continue?state="+loc.Query().Get("state"), nil)
	rec = reviewMFA(t, f, rec, secret, false)
	form := reviewConsent(t, f, rec)
	reviewCode(t, f.b.do(t, "POST", "/u/consent", form))
	u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	if _, ok := u.AppMetadata["remove"]; ok {
		t.Error("app deletion restored")
	}
	if _, ok := u.UserMetadata["remove"]; ok {
		t.Error("user deletion restored")
	}
	if u.AppMetadata["keep"] != "invited" || u.AppMetadata["other"] != "value" {
		t.Fatal(u.AppMetadata)
	}
}
func TestHostedInvitationDenialRetiresFirstFactor(t *testing.T) {
	f := newMFAFixture(t)
	args := reviewInvitation(t, f, "spa", "")
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('runs',(e.user.app_metadata.runs||0)+1);a.access.deny('stop')}`)
	_, state, csrf := f.b.begin(t, args...)
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}}
	savedCookies := map[string]*http.Cookie{}
	for k, v := range f.b.cookies {
		savedCookies[k] = v
	}
	for i := 0; i < 2; i++ {
		for k, v := range savedCookies {
			f.b.cookies[k] = v
		}
		// Reopen the original form, as a second tab with its original credential.
		f.b.do(t, "GET", "/u/login?state="+state, nil)
		f.b.do(t, "POST", "/u/login", form)
	}
	u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
	if u.AppMetadata["runs"] != float64(1) {
		t.Fatal("Action repeated", u.AppMetadata)
	}
	if _, err := f.st.OrganizationsII().GetInvitation(context.Background(), f.tn.ID, args[1], "invite"); err != nil {
		t.Fatal("denial consumed invitation", err)
	}
}

func reviewCode(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("code missing: %d %s %s", rec.Code, loc, rec.Body)
	}
}

func TestPendingActionRedirectSelectsItsOwnIdentity(t *testing.T) {
	f := newMFAFixture(t)
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.example/');exports.onContinuePostLogin=()=>{}`)
	first := reviewLogin(t, f)
	second := reviewLogin(t, f)
	for _, rec := range []*httptest.ResponseRecorder{first, second} {
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Host != "step.example" {
			t.Fatal(loc)
		}
		reviewCode(t, f.b.do(t, "GET", "/continue?state="+loc.Query().Get("state"), nil))
	}
}
func TestHostedInvitationFirstFactorTransitionOnce(t *testing.T) {
	f := newMFAFixture(t)
	args := reviewInvitation(t, f, "spa", "")
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.example/');exports.onContinuePostLogin=()=>{}`)
	_, state, csrf := f.b.begin(t, args...)
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}}
	saved := map[string]*http.Cookie{}
	for k, v := range f.b.cookies {
		saved[k] = v
	}
	first := f.b.do(t, "POST", "/u/login", form)
	for k, v := range saved {
		f.b.cookies[k] = v
	}
	f.b.do(t, "GET", "/u/login?state="+state, nil)
	f.b.do(t, "POST", "/u/login", form)
	executions, err := f.st.Actions().ListExecutions(context.Background(), f.tn.ID, store.ExecutionFilter{})
	if err != nil || len(executions) != 1 {
		t.Fatalf("duplicate first-factor Actions: %d %v", len(executions), err)
	}
	loc, _ := url.Parse(first.Header().Get("Location"))
	reviewCode(t, f.b.do(t, "GET", "/continue?state="+loc.Query().Get("state"), nil))
}
func TestSSOIgnoresRevokedUnrelatedPending(t *testing.T) {
	f := newMFAFixture(t)
	appCode(t, reviewLogin(t, f))
	rec := reviewLogin(t, f, append(reviewConsentArgs, "prompt", "login")...)
	reviewConsent(t, f, rec)
	for name := range f.b.cookies {
		if id, ok := strings.CutPrefix(name, session.PendingCookiePrefix); ok {
			if err := f.st.AuthTransactions().Delete(context.Background(), f.tn.ID, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
	appCode(t, f.b.do(t, "GET", "/authorize?"+q.Encode(), nil))
}

func TestHostedInvitationConcurrentFirstFactors(t *testing.T) {
	f := newMFAFixture(t)
	args := reviewInvitation(t, f, "spa", "")
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.example/');exports.onContinuePostLogin=()=>{}`)
	_, state, csrf := f.b.begin(t, args...)
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {aliceLogin}, "password": {"alice password 1"}, "hosted_revision": {f.b.formRevisions[state]}}
	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		b := f.env.browser(f.b.host)
		for k, v := range f.b.cookies {
			b.cookies[k] = v
		}
		go func() { done <- b.send("POST", "/u/login", form) }()
	}
	redirects := 0
	for i := 0; i < 2; i++ {
		rec := <-done
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Host == "step.example" {
			redirects++
		}
	}
	executions, err := f.st.Actions().ListExecutions(context.Background(), f.tn.ID, store.ExecutionFilter{})
	if err != nil || len(executions) != 1 || redirects != 1 {
		t.Fatalf("duplicate Actions: executions=%d redirects=%d err=%v", len(executions), redirects, err)
	}
	if _, err = f.st.OrganizationsII().GetInvitation(context.Background(), f.tn.ID, args[1], "invite"); err != nil {
		t.Fatal("pending invitation consumed", err)
	}
}

// crossSitePost sends only cookies permitted on a cross-site form POST; Lax
// and Strict credentials are withheld. Cookie policy is tested, not bypassed.
func crossSitePost(b *browser, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://"+b.host+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://external.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	for _, c := range b.cookies {
		if c.SameSite == http.SameSiteNoneMode && c.Secure && strings.HasPrefix(path, c.Path) {
			r.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	b.e.srv.ServeHTTP(rec, r)
	return rec
}
func TestCrossSitePostContinuePendingIdentity(t *testing.T) {
	f := newMFAFixture(t)
	reviewAction(t, f, `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://external.example/');exports.onContinuePostLogin=(e,a)=>{if(e.request.body.answer!=='yes')throw Error('lost form')}`)
	rec := reviewLogin(t, f)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	reviewCode(t, crossSitePost(f.b, "/continue", url.Values{"state": {loc.Query().Get("state")}, "answer": {"yes"}}))
}
func TestCrossSitePostLogoutRevokesPendingConsent(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "existing"}[existing], func(t *testing.T) {
			f := newMFAFixture(t)
			if existing {
				appCode(t, reviewLogin(t, f))
			}
			f.policy(t, "otp")
			secret := f.enrolled(t, "otp", true)
			form := reviewConsent(t, f, reviewMFA(t, f, reviewLogin(t, f, append(reviewConsentArgs, "prompt", "login")...), secret, false))
			old := f.srv
			logout := &oidc.Handlers{Store: f.st, Sessions: f.h.Sessions, Now: f.h.Now}
			f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oidc/logout" {
					tenantHandler(logout.OidcLogout, f.st).ServeHTTP(w, r)
					return
				}
				old.ServeHTTP(w, r)
			})
			out := url.Values{}
			if existing {
				rows, _ := f.st.Sessions().ListByUser(context.Background(), f.tn.ID, f.uid)
				out.Set("logout_hint", rows[0].ID)
			}
			rec := crossSitePost(f.b, "/oidc/logout", out)
			if rec.Code >= 400 {
				t.Fatal(rec.Code, rec.Body)
			}
			// Retain all pre-logout cookies: even an open old tab cannot regain authority.
			rec = f.b.do(t, "POST", "/u/consent", form)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if loc.Query().Get("code") != "" {
				t.Fatal("cross-site logout left pending authority")
			}
		})
	}
}
func TestInvitationAdmissionPolicyResponse(t *testing.T) {
	for _, kind := range []string{"unverified", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			f := newMFAFixture(t)
			email := ""
			if kind == "mismatch" {
				email = "other@example.test"
			}
			args := reviewInvitation(t, f, "spa", email)
			if kind == "unverified" {
				u, _ := f.st.Users().Get(context.Background(), f.tn.ID, f.uid)
				u.EmailVerified = false
				_ = f.st.Users().Update(context.Background(), u)
			}
			rec := reviewLogin(t, f, args...)
			assertInvitationRefusal(t, rec, "app-state")
		})
	}
}
func assertInvitationRefusal(t *testing.T, rec *httptest.ResponseRecorder, state string) {
	t.Helper()
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "app.acme.test" || loc.Path != "/cb" || loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != state {
		t.Fatalf("invitation refusal: %d %s", rec.Code, loc)
	}
}
func TestSocialInvitationAdmissionPolicyResponse(t *testing.T) {
	s := newSocialEnv(t)
	ctx := context.Background()
	toApp(t, s.explicitLogin(t, s.browser("acme.example.test"), s.idp, "corp", "Invited"), "app.acme.test")
	o, _, _ := organizationFixture(t, s.env, store.OrgBehaviorNoPrompt, true, true)
	if err := s.st.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: o.TenantID, OrganizationID: o.ID, ConnectionID: "con_corp", IsEnabled: true, IsEnabledSet: true, ShowAsButton: true}, true); err != nil {
		t.Fatal(err)
	}
	inv := &store.OrganizationInvitation{TenantID: o.TenantID, OrganizationID: o.ID, ID: "social-invite", ClientID: "spa", InviteeEmail: "different@idp.example", ConnectionID: "con_corp", TicketHash: orglogin.InvitationTicketHash("bearer"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.st.OrganizationsII().CreateInvitation(ctx, inv); err != nil {
		t.Fatal(err)
	}
	b := s.browser("acme.example.test")
	page := s.authorizeTo(t, b, "spa", "organization", o.ID, "invitation", "bearer", "connection", "corp", "state", "social-state")
	rec := b.do(t, "GET", page, nil)
	callback := s.idp.authorize(t, providerURL(t, rec), "Invited")
	rec = b.do(t, "GET", callback, nil)
	assertInvitationRefusal(t, rec, "social-state")
}
