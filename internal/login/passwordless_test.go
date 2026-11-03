package login

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/passwordless"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type pwlSMS struct {
	mu   sync.Mutex
	msgs []phone.Message
}

func (f *pwlSMS) Send(_ context.Context, _ string, _ phone.Route, m phone.Message) (phone.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return phone.Result{}, nil
}

func (f *pwlSMS) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

func (f *pwlSMS) last(t *testing.T) phone.Message {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		t.Fatal("no SMS sent")
	}
	return f.msgs[len(f.msgs)-1]
}

type pwlMail struct {
	mu   sync.Mutex
	msgs []email.PasswordlessEmail
}

func (f *pwlMail) SendPasswordless(_ context.Context, m email.PasswordlessEmail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	return nil
}

func (f *pwlMail) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

func (f *pwlMail) last(t *testing.T) email.PasswordlessEmail {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		t.Fatal("no email sent")
	}
	return f.msgs[len(f.msgs)-1]
}

type pwlEvents struct {
	mu     sync.Mutex
	events []logs.Event
}

func (r *pwlEvents) Record(_ context.Context, e logs.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *pwlEvents) of(typ string) []logs.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []logs.Event
	for _, e := range r.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

type pwlFixture struct {
	*env
	tn     *store.Tenant
	sms    *pwlSMS
	mail   *pwlMail
	events *pwlEvents
	svc    *passwordless.Service
}

const pwlNumber = "+14155550123"

// enablePasswordless adds the email and sms connections (enabled for spa),
// the passwordless service with fake senders, and the hosted code routes.
func enablePasswordless(t *testing.T, e *env) *pwlFixture {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	for i, c := range []*store.Connection{
		{TenantID: tn.ID, ID: "con_email", Name: "email", Strategy: "email", EnabledClients: []string{"spa"}, BruteForceProtection: true},
		{TenantID: tn.ID, ID: "con_sms", Name: "sms", Strategy: "sms", EnabledClients: []string{"spa"}, BruteForceProtection: true},
	} {
		c.CreatedAt = fixedNow().Add(time.Duration(i) * time.Second)
		if err := e.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := &pwlFixture{env: e, tn: tn, sms: &pwlSMS{}, mail: &pwlMail{}, events: &pwlEvents{}}
	p.svc = &passwordless.Service{Store: e.st, Wrapper: w, SMS: p.sms, Email: p.mail, Recorder: p.events, Now: e.h.Now, Log: e.h.Log}
	e.h.Passwordless = p.svc
	e.h.Recorder = p.events
	if e.h.Authz.Wrapper == nil {
		e.h.Authz.Wrapper = w
	}
	redirect := &passwordless.Handlers{Service: p.svc, Authz: e.h.Authz, Sessions: e.h.Sessions, Log: e.h.Log}
	old := e.srv
	mux := http.NewServeMux()
	for _, path := range []string{"/u/login-passwordless-email-code", "/u/login-passwordless-sms-otp"} {
		mux.HandleFunc("GET "+path, e.h.PasswordlessCodePage)
		mux.HandleFunc("POST "+path, e.h.PasswordlessCodeSubmit)
	}
	mux.HandleFunc("GET /passwordless/verify_redirect", redirect.VerifyRedirect)
	mux.HandleFunc("POST /passwordless/verify_redirect", redirect.VerifyRedirectConfirm)
	mux.Handle("/", old)
	resolved := tenant.NewResolver(e.st.Tenants(), "", false).Middleware(mux)
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resolved.ServeHTTP(w, r.WithContext(logs.WithRecorder(r.Context(), p.events)))
	})
	return p
}

// noFullNumber fails when any recorded event carries the full number.
func (r *pwlEvents) noFullNumber(t *testing.T, number string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if strings.Contains(fmt.Sprintf("%+v", e), number) {
			t.Errorf("event %s carries the full number: user_name=%q", e.Type, e.UserName)
		}
	}
}

// sendCode submits the passwordless identifier page and follows the
// redirect to the code page.
func (p *pwlFixture) sendCode(t *testing.T, b *browser, state, csrf, identifier string, extra ...string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {identifier}}
	for i := 0; i+1 < len(extra); i += 2 {
		form.Set(extra[i], extra[i+1])
	}
	return b.do(t, "POST", "/u/login", form)
}

// login runs a whole hosted email-code login in b and returns the final
// response (the redirect to the application on success).
func (p *pwlFixture) loginEmail(t *testing.T, b *browser, addr string, extra ...string) *httptest.ResponseRecorder {
	t.Helper()
	_, state, csrf := b.begin(t, append([]string{"connection", "email"}, extra...)...)
	sent := p.sendCode(t, b, state, csrf, addr)
	if sent.Code != http.StatusSeeOther {
		t.Fatalf("send = %d %s", sent.Code, sent.Body)
	}
	page := b.do(t, "GET", sent.Header().Get("Location"), nil)
	if page.Code != http.StatusOK {
		t.Fatalf("code page = %d %s", page.Code, page.Body)
	}
	return b.do(t, "POST", "/u/login-passwordless-email-code", url.Values{"state": {state}, "csrf": {csrf}, "code": {p.mail.last(t).Code}})
}

func appCode(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc == nil || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("want redirect with code, got %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	return loc
}

func (p *pwlFixture) users(t *testing.T) []*store.User {
	t.Helper()
	users, _, err := p.st.Users().List(context.Background(), p.tn.ID, nil, store.UserSort{Field: "user_id"}, store.Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return users
}

func (p *pwlFixture) userByEmail(t *testing.T, addr string) *store.User {
	t.Helper()
	u, err := p.st.Users().FindByLogin(context.Background(), p.tn.ID, "email", addr)
	if err != nil {
		t.Fatalf("user %s: %v", addr, err)
	}
	return u
}

func TestHostedEmailCodeLogin(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	before := len(p.users(t))
	b := p.browser("acme.example.test")
	page, state, csrf := b.begin(t, "connection", "email")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="username"`) || strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("identifier page = %d %s", page.Code, page.Body)
	}
	sent := p.sendCode(t, b, state, csrf, " Ada@Example.TEST ")
	if sent.Code != http.StatusSeeOther || !strings.HasPrefix(sent.Header().Get("Location"), "/u/login-passwordless-email-code?") {
		t.Fatalf("send = %d %s %s", sent.Code, sent.Header().Get("Location"), sent.Body)
	}
	m := p.mail.last(t)
	if m.To != "ada@example.test" || m.Code == "" || m.Link != "" || m.ClientID != "spa" {
		t.Fatalf("email = %+v", m)
	}
	codePage := b.do(t, "GET", sent.Header().Get("Location"), nil)
	if codePage.Code != http.StatusOK || !strings.Contains(codePage.Body.String(), "ada@example.test") || !strings.Contains(codePage.Body.String(), `name="code"`) {
		t.Fatalf("code page = %d %s", codePage.Code, codePage.Body)
	}
	// The SMS screen is not this transaction's.
	if rec := b.do(t, "GET", "/u/login-passwordless-sms-otp?state="+state, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("other screen = %d", rec.Code)
	}
	wrong := b.do(t, "POST", "/u/login-passwordless-email-code", url.Values{"state": {state}, "csrf": {csrf}, "code": {"000000"}})
	if wrong.Code != http.StatusBadRequest || !strings.Contains(wrong.Body.String(), `role="alert"`) || b.cookies[session.CookieName] != nil {
		t.Fatalf("wrong code = %d %s", wrong.Code, wrong.Body)
	}
	if len(p.events.of("f")) != 1 {
		t.Fatalf("wrong code not logged: %+v", p.events.events)
	}
	if strings.Contains(p.logs.String(), m.Code) {
		t.Fatal("code in server log")
	}
	done := b.do(t, "POST", "/u/login-passwordless-email-code", url.Values{"state": {state}, "csrf": {csrf}, "code": {m.Code}})
	appCode(t, done)
	u := p.userByEmail(t, "ada@example.test")
	if !u.EmailVerified || !strings.HasPrefix(u.UserID, "email|") || len(p.users(t)) != before+1 {
		t.Fatalf("signup user = %+v", u)
	}
	if len(p.events.of("ss")) != 1 {
		t.Fatal("signup not logged")
	}
	if b.cookies[session.CookieName] == nil {
		t.Fatal("no session after passwordless login")
	}

	// Existing user: a second login reuses the account.
	b2 := p.browser("acme.example.test")
	appCode(t, p.loginEmail(t, b2, "ada@example.test"))
	if again := p.userByEmail(t, "ada@example.test"); again.UserID != u.UserID || len(p.users(t)) != before+1 || again.LoginsCount != 2 {
		t.Fatalf("existing user = %+v (users %d)", again, len(p.users(t)))
	}
}

func TestHostedSMSCodeLogin(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	b := p.browser("acme.example.test")
	_, state, csrf := b.begin(t, "connection", "sms")
	sent := p.sendCode(t, b, state, csrf, pwlNumber)
	if sent.Code != http.StatusSeeOther || !strings.HasPrefix(sent.Header().Get("Location"), "/u/login-passwordless-sms-otp?") {
		t.Fatalf("send = %d %s %s", sent.Code, sent.Header().Get("Location"), sent.Body)
	}
	m := p.sms.last(t)
	if m.To != pwlNumber || m.Code == "" || m.Type != "passwordless" {
		t.Fatalf("sms = %+v", m)
	}
	cs := p.events.of("cs")
	if len(cs) != 1 || strings.Contains(cs[0].UserName, "5550123") {
		t.Fatalf("cs events = %+v", cs)
	}
	page := b.do(t, "GET", sent.Header().Get("Location"), nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `autocomplete="one-time-code"`) {
		t.Fatalf("code page = %d %s", page.Code, page.Body)
	}
	appCode(t, b.do(t, "POST", "/u/login-passwordless-sms-otp", url.Values{"state": {state}, "csrf": {csrf}, "code": {m.Code}}))
	users, err := p.st.Phone().FindUsersByPhone(context.Background(), p.tn.ID, "sms", pwlNumber)
	if err != nil || len(users) != 1 || !users[0].PhoneVerified {
		t.Fatalf("sms user = %+v %v", users, err)
	}
	if strings.Contains(p.logs.String(), m.Code) || strings.Contains(p.logs.String(), pwlNumber) {
		t.Fatal("code or full number in server log")
	}
	if len(p.events.of("s")) != 1 || len(p.events.of("ss")) != 1 {
		t.Fatalf("success events = %+v", p.events.events)
	}
	p.events.noFullNumber(t, pwlNumber)
	// A later silent authorization records its events with the session user.
	q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
	appCode(t, b.do(t, "GET", "/authorize?"+q.Encode(), nil))
	if len(p.events.of("ssa")) != 1 {
		t.Fatalf("no ssa event for the silent authorization: %+v", p.events.events)
	}
	p.events.noFullNumber(t, pwlNumber)
}

func TestHostedResendObeysBudget(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	b := p.browser("acme.example.test")
	_, state, csrf := b.begin(t, "connection", "sms")
	if rec := p.sendCode(t, b, state, csrf, pwlNumber); rec.Code != http.StatusSeeOther {
		t.Fatalf("send = %d %s", rec.Code, rec.Body)
	}
	b.do(t, "GET", "/u/login-passwordless-sms-otp?state="+state, nil)
	first := p.sms.last(t).Code
	budget := phonerules.Limits.IdentifierSendsPerHour
	for i := 1; i < budget; i++ {
		rec := b.do(t, "POST", "/u/login-passwordless-sms-otp", url.Values{"state": {state}, "csrf": {csrf}, "action": {"resend"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("resend %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	if p.sms.count() != budget {
		t.Fatalf("sent %d, want %d", p.sms.count(), budget)
	}
	over := b.do(t, "POST", "/u/login-passwordless-sms-otp", url.Values{"state": {state}, "csrf": {csrf}, "action": {"resend"}})
	if over.Code != http.StatusTooManyRequests || !strings.Contains(over.Body.String(), `role="alert"`) || p.sms.count() != budget {
		t.Fatalf("over budget = %d (sent %d) %s", over.Code, p.sms.count(), over.Body)
	}
	if len(p.events.of("limit_phone")) != 1 {
		t.Fatalf("limit_phone not logged: %+v", p.events.events)
	}
	// Only the latest code is valid.
	if first != p.sms.last(t).Code {
		rec := b.do(t, "POST", "/u/login-passwordless-sms-otp", url.Values{"state": {state}, "csrf": {csrf}, "code": {first}})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("replaced code = %d", rec.Code)
		}
	}
	appCode(t, b.do(t, "POST", "/u/login-passwordless-sms-otp", url.Values{"state": {state}, "csrf": {csrf}, "code": {p.sms.last(t).Code}}))
}

// P24: the hosted prompt sends codes only, whatever the form asks for.
func TestHostedPasswordlessNeverSendsLink(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	b := p.browser("acme.example.test")
	_, state, csrf := b.begin(t, "connection", "email", "send", "link")
	if rec := p.sendCode(t, b, state, csrf, "ada@example.test", "send", "link"); rec.Code != http.StatusSeeOther {
		t.Fatalf("send = %d %s", rec.Code, rec.Body)
	}
	if m := p.mail.last(t); m.Link != "" || m.Code == "" {
		t.Fatalf("hosted email = %+v", m)
	}
	if len(p.events.of("cls")) != 0 || len(p.events.of("cs")) != 1 {
		t.Fatal("hosted send logged as a link")
	}
}

var confirmField = regexp.MustCompile(`name="(verification_code|state_token)" value="([^"]+)"`)

func confirmForm(t *testing.T, body string) url.Values {
	t.Helper()
	form := url.Values{}
	for _, m := range confirmField.FindAllStringSubmatch(body, -1) {
		form.Set(m[1], strings.ReplaceAll(m[2], "&#43;", "+"))
	}
	if form.Get("state_token") == "" || form.Get("verification_code") == "" {
		t.Fatalf("no confirmation form: %s", body)
	}
	return form
}

// Review Focus 2 and the login-CSRF binding: a scanner's GETs never consume
// an API-started magic link; the user's browser confirms once; a confirmation
// form obtained in another browser is refused.
func TestHostedLinkScannerGet(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	ctx := context.Background()
	c, err := p.st.Clients().Get(ctx, p.tn.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	c.GrantTypes = append(c.GrantTypes, clientrules.GrantPasswordlessOTP)
	if err := p.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	params := url.Values{"redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	if _, err := p.svc.Start(ctx, passwordless.StartInput{TenantID: p.tn.ID, ClientID: "spa", Connection: "email", Email: "ada@example.test", Send: "link", AuthParams: params, Origin: "https://acme.example.test"}); err != nil {
		t.Fatal(err)
	}
	link, _ := url.Parse(p.mail.last(t).Link)
	scanner := p.browser("acme.example.test")
	var scanned string
	for i := 0; i < 2; i++ {
		rec := scanner.do(t, "GET", link.RequestURI(), nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/passwordless/verify_redirect"`) {
			t.Fatalf("scanner GET %d = %d %s", i, rec.Code, rec.Body)
		}
		scanned = rec.Body.String()
	}
	user := p.browser("acme.example.test")
	// A form rendered for another browser (the scanner, or an attacker) is
	// refused in this one, and does not burn the link.
	if rec := user.do(t, "POST", "/passwordless/verify_redirect", confirmForm(t, scanned)); rec.Code != http.StatusBadRequest || user.cookies[session.CookieName] != nil {
		t.Fatalf("cross-browser confirm = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	page := user.do(t, "GET", link.RequestURI(), nil)
	form := confirmForm(t, page.Body.String())
	rec := user.do(t, "POST", "/passwordless/verify_redirect", form)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "s1" {
		t.Fatalf("confirm = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	again := user.do(t, "POST", "/passwordless/verify_redirect", form)
	loc, _ = url.Parse(again.Header().Get("Location"))
	if again.Code != http.StatusFound || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("reuse = %d %s", again.Code, again.Header().Get("Location"))
	}
}

func TestHostedPasswordlessBotPolicy(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	ctx := context.Background()
	tn := mustTenant(t, p.env, "acme")
	tn.ProtectionSettings.Bot.ChallengePasswordlessPolicy = "always"
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "never"
	tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
	tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
	if err := p.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	stub := &captchaStub{}
	p.h.Protection = &protection.Service{Store: p.st, Now: fixedNow, CaptchaVerifier: stub}
	// The password policy governs the password page only.
	if page, _, _ := p.browser("acme.example.test").begin(t); strings.Contains(page.Body.String(), "js.hcaptcha.com") {
		t.Fatal("passwordless policy challenged the password page")
	}
	b := p.browser("acme.example.test")
	page, state, csrf := b.begin(t, "connection", "sms")
	if !strings.Contains(page.Body.String(), "js.hcaptcha.com") {
		t.Fatalf("no challenge on the passwordless page: %s", page.Body)
	}
	rec := p.sendCode(t, b, state, csrf, pwlNumber)
	if rec.Code != http.StatusBadRequest || p.sms.count() != 0 || stub.calls != 0 {
		t.Fatalf("missing proof = %d sent=%d calls=%d", rec.Code, p.sms.count(), stub.calls)
	}
	rec = p.sendCode(t, b, state, csrf, pwlNumber, "h-captcha-response", "bad")
	if rec.Code != http.StatusBadRequest || p.sms.count() != 0 {
		t.Fatalf("bad proof = %d sent=%d", rec.Code, p.sms.count())
	}
	rec = p.sendCode(t, b, state, csrf, pwlNumber, "h-captcha-response", "good")
	if rec.Code != http.StatusSeeOther || p.sms.count() != 1 || stub.last.Action != "passwordless" || stub.last.TransactionID != state {
		t.Fatalf("good proof = %d sent=%d %+v", rec.Code, p.sms.count(), stub.last)
	}
	// Policy never: no challenge.
	tn.ProtectionSettings.Bot.ChallengePasswordlessPolicy = "never"
	if err := p.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if page, _, _ := p.browser("acme.example.test").begin(t, "connection", "sms"); strings.Contains(page.Body.String(), "js.hcaptcha.com") {
		t.Fatal("challenge shown with policy never")
	}
}

func TestHostedPasswordlessMFAChallenge(t *testing.T) {
	f := newMFAFixture(t)
	p := enablePasswordless(t, f.env)
	f.policy(t, "otp")
	rec := p.loginEmail(t, f.b, "ada@example.test")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Path != "/u/mfa" || loc.Query().Get("code") != "" {
		t.Fatalf("passwordless login with MFA policy = %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHostedPasswordlessOrganization(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "nonmember", true: "auto-membership"}[auto], func(t *testing.T) {
			p := enablePasswordless(t, newEnv(t))
			ctx := context.Background()
			c, err := p.st.Clients().Get(ctx, p.tn.ID, "spa")
			if err != nil {
				t.Fatal(err)
			}
			c.OrganizationUsage = store.OrgUsageRequire
			c.OrganizationRequireBehavior = store.OrgBehaviorNoPrompt
			if err := p.st.Clients().Update(ctx, c); err != nil {
				t.Fatal(err)
			}
			org := &store.Organization{TenantID: p.tn.ID, ID: "org_0000000000000001", Name: "acme-org", DisplayName: "Acme Organization", ThirdPartyClientAccess: "allow"}
			if err := p.st.Organizations().Create(ctx, org, []store.OrganizationConnection{{TenantID: p.tn.ID, OrganizationID: org.ID, ConnectionID: "con_email", AssignMembershipOnLogin: auto, ShowAsButton: true}}); err != nil {
				t.Fatal(err)
			}
			b := p.browser("acme.example.test")
			rec := p.loginEmail(t, b, "ada@example.test", "organization", org.ID)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			u := p.userByEmail(t, "ada@example.test")
			member, err := p.st.Organizations().IsMember(ctx, p.tn.ID, org.ID, u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if member != auto {
				t.Fatalf("member = %v, want %v", member, auto)
			}
			if auto && (rec.Code != http.StatusFound || loc.Query().Get("code") == "") {
				t.Fatalf("member login = %d %s", rec.Code, loc)
			}
			if !auto && loc.Query().Get("error") != "access_denied" {
				t.Fatalf("nonmember login = %d %s", rec.Code, loc)
			}
			// The sms connection is not the organization's: refused.
			b2 := p.browser("acme.example.test")
			q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "organization": {org.ID}, "connection": {"sms"}}
			start := b2.do(t, "GET", "/authorize?"+q.Encode(), nil)
			page := b2.do(t, "GET", start.Header().Get("Location"), nil)
			if page.Code == http.StatusOK && strings.Contains(page.Body.String(), `name="username"`) {
				t.Fatalf("sms offered outside the organization: %s", page.Body)
			}
		})
	}
}

func TestHostedPasswordlessBlockedUser(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	ctx := context.Background()
	appCode(t, p.loginEmail(t, p.browser("acme.example.test"), "ada@example.test"))
	u := p.userByEmail(t, "ada@example.test")

	// Blocked between the send and the code: refused like a password login.
	b := p.browser("acme.example.test")
	_, state, csrf := b.begin(t, "connection", "email")
	if rec := p.sendCode(t, b, state, csrf, "ada@example.test"); rec.Code != http.StatusSeeOther {
		t.Fatalf("send = %d", rec.Code)
	}
	b.do(t, "GET", "/u/login-passwordless-email-code?state="+state, nil)
	u.Blocked = true
	if err := p.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	rec := b.do(t, "POST", "/u/login-passwordless-email-code", url.Values{"state": {state}, "csrf": {csrf}, "code": {p.mail.last(t).Code}})
	if rec.Code != http.StatusForbidden || b.cookies[session.CookieName] != nil || !strings.Contains(rec.Body.String(), "blocked") {
		t.Fatalf("blocked verify = %d %s", rec.Code, rec.Body)
	}
	// A blocked user gets no new code.
	sent := p.mail.count()
	b2 := p.browser("acme.example.test")
	_, state, csrf = b2.begin(t, "connection", "email")
	rec = p.sendCode(t, b2, state, csrf, "ada@example.test")
	if rec.Code != http.StatusForbidden || p.mail.count() != sent {
		t.Fatalf("blocked send = %d (sent %d→%d) %s", rec.Code, sent, p.mail.count(), rec.Body)
	}
}

func TestHostedPasswordlessPromptNone(t *testing.T) {
	p := enablePasswordless(t, newEnv(t))
	b := p.browser("acme.example.test")
	silent := func(extra ...string) *url.URL {
		t.Helper()
		q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
		for i := 0; i+1 < len(extra); i += 2 {
			q.Set(extra[i], extra[i+1])
		}
		rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || loc == nil {
			t.Fatalf("prompt=none = %d %s", rec.Code, rec.Body)
		}
		return loc
	}
	if loc := silent("connection", "email"); loc.Query().Get("error") != "login_required" {
		t.Fatalf("no session = %s", loc)
	}
	appCode(t, p.loginEmail(t, b, "ada@example.test"))
	if loc := silent(); loc.Query().Get("code") == "" {
		t.Fatalf("session reuse = %s", loc)
	}
	// Documented: with connection=email|sms the session is not reused.
	if loc := silent("connection", "email"); loc.Query().Get("error") != "login_required" {
		t.Fatalf("passwordless connection reused the session: %s", loc)
	}
}

func TestIdentifierFirstRoutesToPasswordless(t *testing.T) {
	t.Run("connection=email", func(t *testing.T) {
		e := newEnv(t)
		enableIdentifier(t, e)
		p := enablePasswordless(t, e)
		b := p.browser("acme.example.test")
		_, state, csrf := b.begin(t, "connection", "email")
		rec := p.sendCode(t, b, state, csrf, "ada@example.test")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/u/login-passwordless-email-code?") || p.mail.count() != 1 {
			t.Fatalf("identifier = %d %s", rec.Code, rec.Header().Get("Location"))
		}
		b.do(t, "GET", rec.Header().Get("Location"), nil)
		appCode(t, b.do(t, "POST", "/u/login-passwordless-email-code", url.Values{"state": {state}, "csrf": {csrf}, "code": {p.mail.last(t).Code}}))
		// Without connection the database connection keeps the password step.
		b2 := p.browser("acme.example.test")
		page, state2, csrf2 := b2.begin(t)
		rec = b2.do(t, "POST", "/u/login", url.Values{"state": {state2}, "csrf": {csrf2}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "username": {"alice@acme.test"}})
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/u/login/password?") {
			t.Fatalf("database identifier = %d %s", rec.Code, rec.Header().Get("Location"))
		}
	})
	t.Run("no database connection", func(t *testing.T) {
		e := newEnv(t)
		enableIdentifier(t, e)
		p := enablePasswordless(t, e)
		ctx := context.Background()
		conn := p.conn(t)
		conn.EnabledClients = slices.DeleteFunc(conn.EnabledClients, func(c string) bool { return c == "spa" })
		if err := p.st.Connections().Update(ctx, conn); err != nil {
			t.Fatal(err)
		}
		email, err := p.st.Connections().GetByName(ctx, p.tn.ID, "email")
		if err != nil {
			t.Fatal(err)
		}
		email.EnabledClients = nil
		if err := p.st.Connections().Update(ctx, email); err != nil {
			t.Fatal(err)
		}
		b := p.browser("acme.example.test")
		_, state, csrf := b.begin(t)
		rec := p.sendCode(t, b, state, csrf, pwlNumber)
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/u/login-passwordless-sms-otp?") || p.sms.count() != 1 {
			t.Fatalf("identifier = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
	})
}

var passwordlessTemplateKey = regexp.MustCompile(`\{\{-?\s*t\s+\.(?:Tenant\.)?L\s+"([^"]+)"`)

// Every key the hosted passwordless templates use exists in English.
func TestPasswordlessTemplateKeysInEnglish(t *testing.T) {
	english := i18n.EnglishKeys()
	var used []string
	for _, name := range []string{"passwordless_identifier.html", "passwordless_code.html", "passwordless_link.html"} {
		body, err := os.ReadFile("../ui/templates/" + name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range passwordlessTemplateKey.FindAllStringSubmatch(string(body), -1) {
			used = append(used, m[1])
		}
	}
	for _, screen := range []string{"login-passwordless-email-code", "login-passwordless-sms-otp"} {
		for _, suffix := range passwordlessCodeSuffixes {
			used = append(used, "login-passwordless."+screen+"."+suffix)
		}
	}
	if len(used) < 10 {
		t.Fatalf("too few keys found: %v", used)
	}
	for _, k := range used {
		if !slices.Contains(english, k) {
			t.Errorf("key %q missing from en.json", k)
		}
	}
}
