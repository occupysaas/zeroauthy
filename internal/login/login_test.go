// internal/login/login_test.go
package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

const loginSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    enabled_locales: [en, fr]
    custom_text:
      login:
        fr:
          login:
            title: "Connexion"
            wrong-credentials: "Identifiant ou mot de passe incorrect."
      signup:
        fr:
          signup:
            title: "Créer un compte"
            password-policy-not-conformant: "Mot de passe trop faible."
    clients:
      - {client_id: spa, app_type: spa, grant_types: [authorization_code], callbacks: ["https://app.acme.test/cb"]}
      - {client_id: closed, app_type: spa, grant_types: [authorization_code], callbacks: ["https://closed.acme.test/cb"]}
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [spa]}
      - {name: Invite-Only, enabled_clients: [closed], disable_signup: true}
    users:
      - {connection: Username-Password-Authentication, email: alice@acme.test, password: "alice password 1"}
      - {connection: Username-Password-Authentication, email: carol@acme.test, password: "carol password 1", blocked: true}
  - name: globex
    domains: [globex.example.test]
`

const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

type env struct {
	st  store.Store
	srv http.Handler
	h   *Handlers
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := memory.New()
	f, err := seed.Parse([]byte(loginSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(context.Background(), st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	sm := &session.Manager{Store: st, Now: fixedNow}
	az := &authz.Handlers{Store: st, Sessions: sm, Now: fixedNow}
	h := &Handlers{
		Store: st, Sessions: sm, Authz: az,
		Database:     &identity.Database{Store: st, Now: fixedNow},
		UserThrottle: identity.NewThrottle(3, 15*time.Minute, 15*time.Minute),
		IPThrottle:   identity.NewThrottle(30, 15*time.Minute, 15*time.Minute),
		Now:          fixedNow,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", az.Authorize)
	mux.HandleFunc("GET /u/login", h.LoginPage)
	mux.HandleFunc("POST /u/login", h.LoginSubmit)
	mux.HandleFunc("GET /u/signup", h.SignupPage)
	mux.HandleFunc("POST /u/signup", h.SignupSubmit)
	return &env{st: st, h: h, srv: tenant.NewResolver(st.Tenants(), "", false).Middleware(mux)}
}

// browser is a minimal cookie-keeping client for one host.
type browser struct {
	e       *env
	host    string
	cookies map[string]*http.Cookie
	// acceptLanguage, when set, is sent as the Accept-Language header.
	acceptLanguage string
}

func (e *env) browser(host string) *browser {
	return &browser{e: e, host: host, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(t *testing.T, method, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, "https://"+b.host+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, "https://"+b.host+path, nil)
	}
	if b.acceptLanguage != "" {
		r.Header.Set("Accept-Language", b.acceptLanguage)
	}
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.e.srv.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return rec
}

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// begin runs /authorize for the spa client and returns the login page
// response and the transaction state.
func (b *browser) begin(t *testing.T, extra ...string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	q := url.Values{
		"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"},
		"scope": {"openid"}, "state": {"app-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		q.Set(extra[i], extra[i+1])
	}
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")
	page := b.do(t, "GET", loc.RequestURI(), nil)
	m := csrfField.FindStringSubmatch(page.Body.String())
	if m == nil {
		t.Fatalf("no csrf on page %s: %s", loc, page.Body)
	}
	return page, state, m[1]
}

func TestLoginSuccess(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t, "login_hint", "alice@acme.test")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `value="alice@acme.test"`) || !strings.Contains(page.Body.String(), "/u/signup?state=") {
		t.Fatalf("login page = %d %s", page.Code, page.Body)
	}

	// Review focus 4: case and whitespace insensitive.
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"  ALICE@acme.test "}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Host != "app.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "app-state" {
		t.Fatalf("login = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if b.cookies[session.CookieName] == nil {
		t.Fatal("no session cookie after login")
	}
	if _, ok := b.cookies[authz.TxnCookiePrefix+state]; ok {
		t.Fatal("transaction cookie not cleared")
	}
	u, _ := e.st.Users().FindByLogin(context.Background(), mustTenant(t, e, "acme").ID, "Username-Password-Authentication", "alice@acme.test")
	if u.LoginsCount != 1 || u.LastLogin == nil {
		t.Fatalf("login not recorded: %+v", u)
	}

	// The session now satisfies /authorize directly.
	q := url.Values{"client_id": {"spa"}, "redirect_uri": {"https://app.acme.test/cb"}, "response_type": {"code"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "prompt": {"none"}}
	rec = b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("prompt=none after login = %s", loc)
	}
}

func TestWrongPassword(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Incorrect") || b.cookies[session.CookieName] != nil {
		t.Fatalf("wrong password = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `value="alice@acme.test"`) {
		t.Error("login identifier not kept after a failed attempt")
	}
	// The same transaction can be retried.
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if rec.Code != 302 {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
}

func TestThrottle(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	for i := 0; i < 3; i++ {
		b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
	if rec.Code != http.StatusTooManyRequests || b.cookies[session.CookieName] != nil {
		t.Fatalf("locked login = %d %s", rec.Code, rec.Body)
	}
}

// Review focus 3.
func TestTransactionBinding(t *testing.T) {
	e := newEnv(t)
	good := func(b *browser) (string, string) {
		_, state, csrf := b.begin(t)
		return state, csrf
	}
	creds := func(state, csrf string) url.Values {
		return url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}}
	}

	t.Run("missing txn cookie", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, csrf := good(b)
		delete(b.cookies, authz.TxnCookiePrefix+state)
		if rec := b.do(t, "POST", "/u/login", creds(state, csrf)); rec.Code != 400 || b.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("other browser", func(t *testing.T) {
		victim := e.browser("acme.example.test")
		state, csrf := good(victim)
		attacker := e.browser("acme.example.test")
		if rec := attacker.do(t, "POST", "/u/login", creds(state, csrf)); rec.Code != 400 || attacker.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("wrong csrf", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, _ := good(b)
		if rec := b.do(t, "POST", "/u/login", creds(state, "nope")); rec.Code != 400 || b.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("other tenant", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, csrf := good(b)
		other := &browser{e: e, host: "globex.example.test", cookies: b.cookies}
		if rec := other.do(t, "POST", "/u/login", creds(state, csrf)); rec.Code != 400 || other.cookies[session.CookieName] != nil {
			t.Fatalf("got %d", rec.Code)
		}
	})
	t.Run("expired", func(t *testing.T) {
		b := e.browser("acme.example.test")
		state, csrf := good(b)
		txn, _ := e.st.AuthTransactions().Get(context.Background(), mustTenant(t, e, "acme").ID, state)
		txn.ExpiresAt = fixedNow().Add(-time.Second)
		_ = e.st.AuthTransactions().Delete(context.Background(), txn.TenantID, txn.ID)
		_ = e.st.AuthTransactions().Create(context.Background(), txn)
		rec := b.do(t, "POST", "/u/login", creds(state, csrf))
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "expired") || b.cookies[session.CookieName] != nil {
			t.Fatalf("got %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("unknown state on GET", func(t *testing.T) {
		b := e.browser("acme.example.test")
		if rec := b.do(t, "GET", "/u/login?state=nope", nil); rec.Code != 400 {
			t.Fatalf("got %d", rec.Code)
		}
	})
}

func TestSignup(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")

	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"short"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "at least 8") {
		t.Fatalf("weak password = %d %s", rec.Code, rec.Body)
	}
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"ALICE@acme.test"}, "password": {"long enough pw"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "already exists") {
		t.Fatalf("duplicate = %d %s", rec.Code, rec.Body)
	}
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"long enough pw"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("code") == "" || b.cookies[session.CookieName] == nil {
		t.Fatalf("signup = %d %s", rec.Code, rec.Body)
	}
}

func TestSignupDisabled(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	q := url.Values{
		"client_id": {"closed"}, "redirect_uri": {"https://closed.acme.test/cb"}, "response_type": {"code"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	rec := b.do(t, "GET", "/authorize?"+q.Encode(), nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	page := b.do(t, "GET", loc.RequestURI(), nil)
	if strings.Contains(page.Body.String(), "/u/signup") {
		t.Fatal("signup link shown for a connection with signup disabled")
	}
	signup := b.do(t, "GET", "/u/signup?state="+loc.Query().Get("state"), nil)
	if signup.Code != http.StatusForbidden {
		t.Fatalf("signup page = %d", signup.Code)
	}
}

func mustTenant(t *testing.T, e *env, name string) *store.Tenant {
	t.Helper()
	tn, err := e.st.Tenants().GetByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("POST", "/u/login", nil)
	r.RemoteAddr = "10.0.0.1:4444"
	r.Header.Set("X-Forwarded-For", "spoofed, 203.0.113.9")
	if got := clientIP(r, false); got != "10.0.0.1" {
		t.Errorf("untrusted = %q", got)
	}
	if got := clientIP(r, true); got != "203.0.113.9" {
		t.Errorf("trusted = %q", got)
	}
	r.Header.Del("X-Forwarded-For")
	if got := clientIP(r, true); got != "10.0.0.1" {
		t.Errorf("no header = %q", got)
	}
}

func TestIPThrottle(t *testing.T) {
	e := newEnv(t)
	e.h.IPThrottle = identity.NewThrottle(3, 15*time.Minute, 15*time.Minute)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	var last int
	for i := 0; i < 4; i++ {
		user := "nobody" + string(rune('a'+i)) + "@acme.test"
		last = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {user}, "password": {"wrong"}}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("fourth failure from one IP = %d, want 429", last)
	}
}

func TestSuccessfulLoginsRefundIPAttempt(t *testing.T) {
	e := newEnv(t)
	e.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	for i := 0; i < 5; i++ {
		b := e.browser("acme.example.test")
		_, state, csrf := b.begin(t)
		rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"alice password 1"}})
		if rec.Code != 302 {
			t.Fatalf("login %d = %d %s", i, rec.Code, rec.Body)
		}
	}
}

func TestBlockedUser(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	form := url.Values{"state": {state}, "csrf": {csrf}, "username": {"carol@acme.test"}, "password": {"carol password 1"}}
	// More tries than the per-user maximum: a blocked user is not a failed guess.
	for i := 0; i < 5; i++ {
		rec := b.do(t, "POST", "/u/login", form)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "blocked") || b.cookies[session.CookieName] != nil {
			t.Fatalf("blocked login %d = %d %s", i, rec.Code, rec.Body)
		}
	}
}

// Browsers apply form-action to the redirect chain that follows a form
// submission, so every page with a form must allow the client's origin or
// the final redirect back to the application is blocked.
func TestFormPagesAllowClientOriginInFormAction(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	page, state, csrf := b.begin(t)
	want := "form-action 'self' https://app.acme.test;"
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
		t.Errorf("login page CSP %q lacks %q", csp, want)
	}
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
		t.Errorf("failed login CSP %q lacks %q", csp, want)
	}
	rec = b.do(t, "GET", "/u/signup?state="+state, nil)
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, want) {
		t.Errorf("signup page CSP %q lacks %q", csp, want)
	}
}

func TestSignupIPThrottle(t *testing.T) {
	e := newEnv(t)
	e.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	signup := func(email string) *httptest.ResponseRecorder {
		b := e.browser("acme.example.test")
		_, state, csrf := b.begin(t, "screen_hint", "signup")
		return b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {email}, "password": {"long enough pw"}})
	}
	for _, email := range []string{"u1@acme.test", "u2@acme.test"} {
		if rec := signup(email); rec.Code != http.StatusFound {
			t.Fatalf("signup %s = %d %s", email, rec.Code, rec.Body)
		}
	}
	if rec := signup("u3@acme.test"); rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Too many attempts") {
		t.Fatalf("third signup = %d", rec.Code)
	}
	if _, err := e.st.Users().FindByLogin(context.Background(), mustTenant(t, e, "acme").ID, "Username-Password-Authentication", "u3@acme.test"); err == nil {
		t.Fatal("throttled signup created a user")
	}
}

// Localized policy messages keep the English wording that Reason produced
// before localization.
func TestPolicyMessagesKeepEnglishWording(t *testing.T) {
	errs := []error{
		identity.CheckPassword(store.PasswordPolicy{}, strings.Repeat("x", 300)),
		identity.CheckPassword(store.PasswordPolicy{MinLength: 12}, "short"),
		identity.CheckPassword(store.PasswordPolicy{RequireCharacterClasses: 3}, "alllowercase"),
		identity.CheckUsername("not valid!"),
	}
	for _, err := range errs {
		pe, ok := err.(*identity.PolicyError)
		if !ok || pe.Key == "" {
			t.Fatalf("err = %#v, want a keyed PolicyError", err)
		}
		if got, want := i18n.Default().T(pe.Key, pe.Vars...), capitalize(pe.Reason)+"."; got != want {
			t.Errorf("%s = %q, want %q", pe.Key, got, want)
		}
	}
}

func TestLoginPagesFollowUILocales(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, csrf := b.begin(t, "ui_locales", "fr")
	body := rec.Body.String()
	if !strings.Contains(body, `lang="fr"`) || !strings.Contains(body, "Connexion") || !strings.Contains(body, "Email or username") {
		t.Fatalf("login page not French with English fallback:\n%s", body)
	}
	// A failed login keeps the transaction's language, error included.
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"wrong"}})
	if !strings.Contains(rec.Body.String(), "Identifiant ou mot de passe incorrect.") || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("failed login not French:\n%s", rec.Body)
	}
	rec = b.do(t, "GET", "/u/signup?state="+url.QueryEscape(state), nil)
	if !strings.Contains(rec.Body.String(), "Créer un compte") {
		t.Fatalf("signup not French:\n%s", rec.Body)
	}
}

func TestLoginPageFollowsAcceptLanguageAndPolicyVariables(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, csrf := b.begin(t)
	if !strings.Contains(rec.Body.String(), `lang="en"`) {
		t.Fatal("default must be English")
	}
	// A short password shows the English policy text with ${min} filled in.
	rec = b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"short"}})
	if !strings.Contains(rec.Body.String(), "at least 8 characters") {
		t.Fatalf("policy message:\n%s", rec.Body)
	}
}

func TestLoginPageFollowsAcceptLanguageHeader(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	b.acceptLanguage = "fr-CA,fr;q=0.9"
	rec, _, _ := b.begin(t)
	if !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("Accept-Language not honoured:\n%s", rec.Body)
	}
}

// An error page rendered after the transaction is verified keeps the
// transaction's ui_locales.
func TestPostVerificationErrorPagesKeepUILocales(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "ui_locales", "fr")
	// Drop the connection's enablement so load fails with errNoConnection
	// after the transaction itself verifies.
	tn := mustTenant(t, e, "acme")
	conns, err := e.st.Connections().List(context.Background(), tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range conns {
		if c.Name == "Username-Password-Authentication" {
			c.EnabledClients = nil
			if err := e.st.Connections().Update(context.Background(), c); err != nil {
				t.Fatal(err)
			}
		}
	}
	rec := b.do(t, "GET", "/u/login?state="+url.QueryEscape(state), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("no-connection error not French = %d\n%s", rec.Code, rec.Body)
	}
	rec = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {"x"}})
	if !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("POST no-connection error not French = %d\n%s", rec.Code, rec.Body)
	}
}

// Auth0's signup.signup.password-policy-not-conformant, when the tenant sets
// it for the language, replaces every password policy message.
func TestPasswordPolicyAliasFromSeed(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup", "ui_locales", "fr")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"short"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Mot de passe trop faible.") {
		t.Fatalf("short password in fr = %d\n%s", rec.Code, rec.Body)
	}
}

func TestPolicyTextAlias(t *testing.T) {
	tn := &store.Tenant{CustomText: store.CustomText{
		"signup": {"fr": {"signup": {"password-policy-not-conformant": "Trop faible."}}},
	}}
	fr, en := i18n.New(tn, "fr"), i18n.New(tn, "en")
	for _, err := range []error{
		identity.CheckPassword(store.PasswordPolicy{}, strings.Repeat("x", 300)),
		identity.CheckPassword(store.PasswordPolicy{MinLength: 12}, "short"),
		identity.CheckPassword(store.PasswordPolicy{RequireCharacterClasses: 3}, "alllowercase"),
	} {
		pe := err.(*identity.PolicyError)
		if got := policyText(fr, pe); got != "Trop faible." {
			t.Errorf("%s in fr = %q, want the alias text", pe.Key, got)
		}
		if got, want := policyText(en, pe), en.T(pe.Key, pe.Vars...); got != want {
			t.Errorf("%s in en = %q, want %q", pe.Key, got, want)
		}
	}
	pe := identity.CheckUsername("not valid!").(*identity.PolicyError)
	if got := policyText(fr, pe); got == "Trop faible." {
		t.Error("the alias must not replace the username message")
	}
}

// Without an application name, the subtitle names only the tenant; the
// client ID is never shown to end users.
func TestSubtitleWithAndWithoutClientName(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, _ := b.begin(t)
	body := rec.Body.String()
	if !strings.Contains(body, "Sign in to acme to continue.") || strings.Contains(body, "continue to spa") {
		t.Fatalf("login subtitle without a client name:\n%s", body)
	}
	rec = b.do(t, "GET", "/u/signup?state="+url.QueryEscape(state), nil)
	if body := rec.Body.String(); !strings.Contains(body, "Sign up for acme to continue.") || strings.Contains(body, "continue to spa") {
		t.Fatalf("signup subtitle without a client name:\n%s", body)
	}

	tn := mustTenant(t, e, "acme")
	c, err := e.st.Clients().Get(context.Background(), tn.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	c.Name = "Shop"
	if err := e.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	rec, state, _ = b.begin(t)
	if !strings.Contains(rec.Body.String(), "Sign in to acme to continue to Shop.") {
		t.Fatalf("login subtitle with a client name:\n%s", rec.Body)
	}
	rec = b.do(t, "GET", "/u/signup?state="+url.QueryEscape(state), nil)
	if !strings.Contains(rec.Body.String(), "Sign up for acme to continue to Shop.") {
		t.Fatalf("signup subtitle with a client name:\n%s", rec.Body)
	}
}
