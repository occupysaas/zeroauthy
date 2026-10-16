// internal/authz/handlers_test.go
package authz

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

type env struct {
	*fixture
	h   *Handlers
	srv http.Handler
}

func newEnv(t *testing.T) *env {
	f := newFixture(t)
	sm := &session.Manager{Store: f.st, Now: fixedNow}
	h := &Handlers{Store: f.st, Sessions: sm, Now: fixedNow}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", h.Authorize)
	return &env{fixture: f, h: h, srv: contract.Wrap(t, tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux))}
}

func (e *env) get(t *testing.T, q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "https://acme.example.test/authorize?"+q.Encode(), nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, r)
	return rec
}

// login creates a session for alice directly and returns its cookie.
func (e *env) login(t *testing.T, authTime time.Time) *http.Cookie {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, "Username-Password-Authentication", authTime); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

func location(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNoSessionStartsLogin(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, goodQuery())
	loc := location(t, rec)
	if loc.Path != "/u/login" || loc.Query().Get("state") == "" {
		t.Fatalf("Location = %s", loc)
	}
	txnID := loc.Query().Get("state")
	var txnCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == TxnCookiePrefix+txnID {
			txnCookie = c
		}
	}
	if txnCookie == nil || !txnCookie.HttpOnly || !txnCookie.Secure || txnCookie.Path != "/u" || txnCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("txn cookie = %+v", txnCookie)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txnID)
	if err != nil {
		t.Fatal(err)
	}
	if txn.CookieHash != secrets.HashToken(txnCookie.Value) || txn.ClientID != "spa" || txn.CSRFToken == "" ||
		txn.Params["redirect_uri"] != "https://app.acme.test/callback" || !txn.ExpiresAt.Equal(fixedNow().Add(TxnLifetime)) {
		t.Fatalf("txn = %+v", txn)
	}

	signup := location(t, e.get(t, with(goodQuery(), "screen_hint", "signup")))
	if signup.Path != "/u/signup" {
		t.Fatalf("screen_hint=signup went to %s", signup)
	}
}

func TestSessionIssuesCode(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-time.Minute))
	loc := location(t, e.get(t, with(goodQuery(), "nonce", "n1", "audience", "https://api.acme.test"), ck))
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != "https://app.acme.test/callback" {
		t.Fatalf("redirected to %s", loc)
	}
	code, state := loc.Query().Get("code"), loc.Query().Get("state")
	if len(code) < 40 || state != "st" {
		t.Fatalf("code=%q state=%q", code, state)
	}
	ac, err := e.st.AuthCodes().Consume(context.Background(), e.tenant.ID, secrets.HashToken(code), fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if ac.ClientID != "spa" || ac.RedirectURI != "https://app.acme.test/callback" || ac.Nonce != "n1" ||
		ac.Audience != "https://api.acme.test" || ac.CodeChallenge != challenge || ac.CodeChallengeMethod != "S256" ||
		strings.Join(ac.Scopes, " ") != "openid profile" || !ac.ExpiresAt.Equal(fixedNow().Add(CodeLifetime)) ||
		!ac.AuthTime.Equal(fixedNow().Add(-time.Minute)) || ac.SessionID == "" {
		t.Fatalf("code = %+v", ac)
	}
}

func TestResponseModes(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())

	frag := location(t, e.get(t, with(goodQuery(), "response_mode", "fragment"), ck))
	fv, _ := url.ParseQuery(frag.Fragment)
	if frag.RawQuery != "" || fv.Get("code") == "" || fv.Get("state") != "st" {
		t.Fatalf("fragment response = %s", frag)
	}

	rec := e.get(t, with(goodQuery(), "response_mode", "form_post"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="https://app.acme.test/callback"`) || !strings.Contains(rec.Body.String(), `name="code"`) {
		t.Fatalf("form_post = %d %s", rec.Code, rec.Body)
	}

	rec = e.get(t, with(goodQuery(), "response_mode", "web_message", "prompt", "none"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "authorization_response") || !strings.Contains(rec.Body.String(), "code") {
		t.Fatalf("web_message = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors https://app.acme.test") {
		t.Fatalf("web_message CSP = %q", rec.Header().Get("Content-Security-Policy"))
	}
}

// Review focus 5.
func TestPromptNoneWithoutSession(t *testing.T) {
	e := newEnv(t)
	loc := location(t, e.get(t, with(goodQuery(), "prompt", "none")))
	if loc.Host != "app.acme.test" || loc.Query().Get("error") != "login_required" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
	rec := e.get(t, with(goodQuery(), "prompt", "none", "response_mode", "web_message"))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "login_required") || strings.Contains(body, "<form") {
		t.Fatalf("web_message login_required = %d %s", rec.Code, body)
	}
}

func TestForcedReauthentication(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow().Add(-10*time.Minute))
	for name, q := range map[string]url.Values{
		"prompt=login":     with(goodQuery(), "prompt", "login"),
		"max_age=0":        with(goodQuery(), "max_age", "0"),
		"max_age exceeded": with(goodQuery(), "max_age", "300"),
		"other connection": with(goodQuery(), "client_id", "web", "redirect_uri", "https://web.acme.test/cb", "connection", "Other-DB", "code_challenge", "", "code_challenge_method", ""),
	} {
		t.Run(name, func(t *testing.T) {
			if loc := location(t, e.get(t, q, ck)); loc.Path != "/u/login" {
				t.Fatalf("Location = %s", loc)
			}
		})
	}
	if loc := location(t, e.get(t, with(goodQuery(), "max_age", "3600"), ck)); loc.Query().Get("code") == "" {
		t.Fatalf("recent session with max_age=3600 should get a code: %s", loc)
	}
	if loc := location(t, e.get(t, with(goodQuery(), "max_age", "0", "prompt", "none"), ck)); loc.Query().Get("error") != "login_required" {
		t.Fatalf("max_age=0 with prompt=none: %s", loc)
	}
}

func TestErrorDelivery(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, with(goodQuery(), "redirect_uri", "https://evil.test/cb"))
	if rec.Code != 400 || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "not registered") {
		t.Fatalf("unregistered redirect = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	loc := location(t, e.get(t, with(goodQuery(), "response_type", "token")))
	if loc.Host != "app.acme.test" || loc.Query().Get("error") != "unsupported_response_type" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestResume(t *testing.T) {
	e := newEnv(t)
	loc := location(t, e.get(t, with(goodQuery(), "response_mode", "fragment")))
	txn, _ := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))

	u, _ := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	rec := httptest.NewRecorder()
	sess, _ := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, "Username-Password-Authentication", fixedNow())

	rec = httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://acme.example.test/u/login", nil)
	e.h.Resume(rec, r, tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}, txn, sess)
	back := location(t, rec)
	fv, _ := url.ParseQuery(back.Fragment)
	if back.Host != "app.acme.test" || fv.Get("code") == "" || fv.Get("state") != "st" {
		t.Fatalf("Resume redirect = %s", back)
	}
	s2, _ := e.st.Sessions().GetByTokenHash(context.Background(), e.tenant.ID, sess.TokenHash)
	if len(s2.ClientIDs) != 1 || s2.ClientIDs[0] != "spa" {
		t.Fatalf("session clients = %v", s2.ClientIDs)
	}
	if _, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, txn.ID); err == nil {
		t.Fatal("transaction not deleted after resume")
	}
}

// A session made through a connection the client does not have enabled must
// not be reused for that client.
func TestSessionConnectionMustBeEnabledForClient(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	q := with(goodQuery(), "client_id", "other-spa", "redirect_uri", "https://other.acme.test/cb")
	if loc := location(t, e.get(t, q, ck)); loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
	loc := location(t, e.get(t, with(q, "prompt", "none"), ck))
	if loc.Host != "other.acme.test" || loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
		t.Fatalf("prompt=none Location = %s", loc)
	}
}

func TestPrivateUseCallbackReceivesCode(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	loc := location(t, e.get(t, with(goodQuery(), "redirect_uri", "com.example.app:/oauth2redirect"), ck))
	if loc.Scheme != "com.example.app" || loc.Path != "/oauth2redirect" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "st" {
		t.Fatalf("Location = %s", loc)
	}
}

// A session whose user was blocked or deleted since login must not get a code.
func TestSessionOfBlockedOrDeletedUser(t *testing.T) {
	for _, name := range []string{"blocked", "deleted"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			ck := e.login(t, fixedNow())
			if name == "blocked" {
				u, _ := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
				u.Blocked = true
				if err := e.st.Users().Update(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			} else { // the store has no user deletion; a session for a missing user is equivalent
				rec := httptest.NewRecorder()
				if _, err := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, "auth0|gone", "Username-Password-Authentication", fixedNow()); err != nil {
					t.Fatal(err)
				}
				ck = rec.Result().Cookies()[0]
			}
			if loc := location(t, e.get(t, goodQuery(), ck)); loc.Path != "/u/login" || loc.Query().Get("code") != "" {
				t.Fatalf("Location = %s", loc)
			}
			loc := location(t, e.get(t, with(goodQuery(), "prompt", "none"), ck))
			if loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
				t.Fatalf("prompt=none Location = %s", loc)
			}
		})
	}
}

func TestFormPostRequiresHTTPCallback(t *testing.T) {
	e := newEnv(t)
	q := with(goodQuery(), "redirect_uri", "com.example.app:/oauth2redirect", "response_mode", "form_post")
	u := location(t, e.get(t, q))
	if u.Scheme != "com.example.app" || u.Query().Get("error") != "invalid_request" ||
		!strings.Contains(u.Query().Get("error_description"), "form_post") {
		t.Fatalf("redirect = %v", u)
	}
}

func TestErrorPageAndFormPostAreLocalized(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, with(goodQuery(), "redirect_uri", "https://evil.test/cb", "ui_locales", "fr"))
	// html/template escapes the apostrophes in the rendered page.
	if rec.Code != 400 || !strings.Contains(html.UnescapeString(rec.Body.String()), "La demande de l'application n'a pas pu aboutir.") ||
		!strings.Contains(rec.Body.String(), "redirect_uri") {
		t.Fatalf("error page = %d %s", rec.Code, rec.Body)
	}
	ck := e.login(t, fixedNow())
	rec = e.get(t, with(goodQuery(), "response_mode", "form_post", "ui_locales", "fr"), ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Poursuivre") || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("form_post = %d %s", rec.Code, rec.Body)
	}
}

func partnerQuery() url.Values {
	q := url.Values{
		"client_id": {"partner"}, "redirect_uri": {"https://partner.example/cb"}, "response_type": {"code"},
		"scope": {"read:things"}, "audience": {"https://api.acme.test"}, "state": {"st"},
		"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"},
	}
	return q
}

func (e *env) grantConsent(t *testing.T, clientID, audience string, scopes ...string) {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.UserGrants().Upsert(context.Background(), &store.UserGrant{
		TenantID: e.tenant.ID, ID: "ugr_test", ClientID: clientID, UserID: u.UserID, Audience: audience,
		Scopes: scopes, CreatedAt: fixedNow(), UpdatedAt: fixedNow(),
	}); err != nil {
		t.Fatal(err)
	}
}

// loginOn starts a session for alice through the named connection; Start
// does not check identities.
func (e *env) loginOn(t *testing.T, connection string, authTime time.Time) *http.Cookie {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, err := e.h.Sessions.Start(context.Background(), rec, httptest.NewRequest("GET", "/", nil), e.tenant, u.UserID, connection, authTime); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

func TestThirdPartyGoesToConsent(t *testing.T) {
	e := newEnv(t)
	rec := e.get(t, partnerQuery(), e.login(t, fixedNow()))
	loc := location(t, rec)
	if loc.Path != "/u/consent" || loc.Query().Get("state") == "" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestThirdPartyConsentCoveredIssuesCode(t *testing.T) {
	e := newEnv(t)
	e.grantConsent(t, "partner", "https://api.acme.test", "read:things")
	loc := location(t, e.get(t, partnerQuery(), e.login(t, fixedNow())))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestPromptNoneConsentRequired(t *testing.T) {
	e := newEnv(t)
	// partner-open redirects errors (allow_always); partner would show a page.
	q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
		"audience": {"https://api.acme.test"}, "scope": {"read:things"}, "state": {"st"}, "prompt": {"none"}}
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if got := loc.Query().Get("error"); got != "consent_required" { // O5
		t.Fatalf("error = %q (%s)", got, loc)
	}
}

func TestProtectedClientErrorsArePages(t *testing.T) {
	e := newEnv(t)
	for name, q := range map[string]url.Values{
		"prompt=none, consent needed": func() url.Values { q := partnerQuery(); q.Set("prompt", "none"); return q }(),
		"no audience (strict)":        func() url.Values { q := partnerQuery(); q.Del("audience"); return q }(),
	} {
		rec := e.get(t, q, e.login(t, fixedNow()))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: status %d Location %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	q := partnerQuery()
	q.Set("prompt", "none")
	if rec := e.get(t, q); rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" { // no session: login_required as a page
		t.Errorf("no session: status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestStrictRejectsParameters(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"request_uri", "request", "id_token_hint", "claims", "login_ticket", "screen_hint"} {
		q := partnerQuery()
		q.Set(p, "x")
		// A protected client's errors are pages (D-0027), never redirects.
		rec := e.get(t, q)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), p+" is not supported") {
			t.Errorf("%s: status %d Location %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestStrictRequiresPKCE(t *testing.T) {
	e := newEnv(t)
	q := partnerQuery()
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	rec := e.get(t, q)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "must use PKCE") {
		t.Fatalf("status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDenyAllUnderProtectionShowsErrorPage(t *testing.T) {
	e := newEnv(t)
	q := partnerQuery()
	q.Set("audience", "https://locked.acme.test")
	rec := e.get(t, q, e.login(t, fixedNow()))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDenyAllAllowAlwaysRedirects(t *testing.T) {
	e := newEnv(t)
	q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
		"audience": {"https://locked.acme.test"}, "state": {"st"}}
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Host != "open.example" || loc.Query().Get("error") != "invalid_request" { // O7
		t.Fatalf("Location = %s", loc)
	}
}

func TestLocalhostConfirmation(t *testing.T) {
	e := newEnv(t)
	q := url.Values{"client_id": {"local"}, "redirect_uri": {"http://localhost:5000/cb"}, "response_type": {"code"},
		"state": {"st"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}}
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Path != "/u/consent" {
		t.Fatalf("Location = %s", loc)
	}
	q.Set("prompt", "none")
	loc = location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Query().Get("error") != "consent_required" { // O5
		t.Fatalf("Location = %s", loc)
	}
}

func TestPromptConsentSurvivesLogin(t *testing.T) {
	e := newEnv(t)
	q := goodQuery()
	q.Set("prompt", "login consent")
	loc := location(t, e.get(t, q))
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["prompt"] != "consent" {
		t.Fatalf("prompt kept in transaction = %q, want consent", txn.Params["prompt"])
	}
}

func TestThirdPartySessionOnNonDomainConnectionLogsInAgain(t *testing.T) {
	e := newEnv(t)
	e.grantConsent(t, "partner", "https://api.acme.test", "read:things")
	cookie := e.loginOn(t, "Other-DB", fixedNow()) // a session through a non-domain connection
	loc := location(t, e.get(t, partnerQuery(), cookie))
	if loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
}

// txnFor stores a transaction for q; consent marks it as a consent transaction.
func (e *env) txnFor(t *testing.T, q url.Values, consent bool) *store.AuthTransaction {
	t.Helper()
	req := ParseRequest(q)
	params := req.Params()
	if consent {
		params[stageKey] = stageConsent
	}
	txn := &store.AuthTransaction{
		TenantID: e.tenant.ID, ID: secrets.RandomString(24), CookieHash: "h", CSRFToken: "c",
		ClientID: req.ClientID, Params: params, ExpiresAt: fixedNow().Add(TxnLifetime), CreatedAt: fixedNow(),
	}
	if err := e.st.AuthTransactions().Create(context.Background(), txn); err != nil {
		t.Fatal(err)
	}
	return txn
}

func (e *env) session(t *testing.T, ck *http.Cookie) *store.LoginSession {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(ck)
	s, err := e.h.Sessions.Current(context.Background(), r, e.tenant)
	if err != nil || s == nil {
		t.Fatalf("session: %v %v", s, err)
	}
	return s
}

func (e *env) res() tenant.Resolved {
	return tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}
}

func (e *env) consent(t *testing.T, txn *store.AuthTransaction, ck *http.Cookie, accepted bool) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://acme.example.test/u/consent", nil)
	sess := e.session(t, ck)
	if _, bound := txn.Params[sessionKey]; !bound && txn.Params[stageKey] == stageConsent {
		txn.Params[sessionKey] = sess.ID // as startConsent does
	}
	e.h.Consent(rec, r, e.res(), txn, sess, accepted)
	return rec
}

func (e *env) userGrant(t *testing.T, clientID, audience string) *store.UserGrant {
	t.Helper()
	u, _ := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	g, err := e.st.UserGrants().Find(context.Background(), e.tenant.ID, clientID, u.UserID, audience)
	if err != nil {
		return nil
	}
	return g
}

func TestConsentRefusesLoginTransaction(t *testing.T) {
	e := newEnv(t)
	q := partnerQuery()
	q.Set("prompt", "login")
	rec := e.consent(t, e.txnFor(t, q, false), e.login(t, fixedNow()), true)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || e.userGrant(t, "partner", "https://api.acme.test") != nil {
		t.Fatalf("status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestConsentRestartsLoginOnUnusableSession(t *testing.T) {
	e := newEnv(t)
	txn := e.txnFor(t, partnerQuery(), true)
	rec := e.consent(t, txn, e.loginOn(t, "Other-DB", fixedNow()), true)
	loc := location(t, rec)
	if loc.Path != "/u/login" || e.userGrant(t, "partner", "https://api.acme.test") != nil {
		t.Fatalf("Location = %s", loc)
	}
}

func TestResumeRefusesConsentTransaction(t *testing.T) {
	e := newEnv(t)
	txn := e.txnFor(t, partnerQuery(), true)
	rec := httptest.NewRecorder()
	e.h.Resume(rec, httptest.NewRequest("POST", "https://acme.example.test/u/login", nil), e.res(), txn, e.session(t, e.login(t, fixedNow())))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestConsentAcceptedWritesGrantAndMerges(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	loc := location(t, e.consent(t, e.txnFor(t, partnerQuery(), true), ck, true))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
	g := e.userGrant(t, "partner", "https://api.acme.test")
	if g == nil || strings.Join(g.Scopes, " ") != "read:things" {
		t.Fatalf("grant = %+v", g)
	}
	// A second accept with another scope merges into the same grant.
	e.grantConsent(t, "partner", "https://api.acme.test", "other:scope")
	loc = location(t, e.consent(t, e.txnFor(t, partnerQuery(), true), ck, true))
	if loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
	g = e.userGrant(t, "partner", "https://api.acme.test")
	if g == nil || !slices.Contains(g.Scopes, "read:things") || !slices.Contains(g.Scopes, "other:scope") {
		t.Fatalf("merged grant = %+v", g)
	}
}

func TestConsentDeclined(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	rec := e.consent(t, e.txnFor(t, partnerQuery(), true), ck, false)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("partner: status %d Location %q", rec.Code, rec.Header().Get("Location"))
	}
	q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
		"audience": {"https://api.acme.test"}, "scope": {"read:things"}, "state": {"st"}}
	loc := location(t, e.consent(t, e.txnFor(t, q, true), ck, false))
	if loc.Host != "open.example" || loc.Query().Get("error") != "access_denied" {
		t.Fatalf("Location = %s", loc)
	}
	if e.userGrant(t, "partner", "https://api.acme.test") != nil || e.userGrant(t, "partner-open", "https://api.acme.test") != nil {
		t.Fatal("a grant was written")
	}
}

func TestConsentView(t *testing.T) {
	e := newEnv(t)
	sess := e.session(t, e.login(t, fixedNow()))
	view := func(q url.Values) *ConsentView {
		t.Helper()
		v, err := e.h.ConsentView(context.Background(), e.res(), e.txnFor(t, q, true), sess)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	v := view(partnerQuery())
	if v.Confirmation || !v.ThirdParty || v.CallbackDomain != "partner.example" || v.APIName != "API" || strings.Join(v.Scopes, ",") != "read:things" {
		t.Fatalf("partner view = %+v", v)
	}
	local := url.Values{"client_id": {"local"}, "redirect_uri": {"http://localhost:5000/cb"}, "response_type": {"code"},
		"state": {"st"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}}
	if v := view(local); !v.Confirmation || v.ThirdParty || v.CallbackDomain != "localhost" {
		t.Fatalf("local view = %+v", v)
	}
	// Custom scheme: the callback domain is the scheme.
	if _, err := e.h.ConsentView(context.Background(), e.res(), e.txnFor(t, partnerQuery(), false), sess); err == nil {
		t.Fatal("unmarked transaction accepted")
	}
	c, _ := e.st.Clients().Get(context.Background(), e.tenant.ID, "local")
	c.Callbacks = append(c.Callbacks, "com.example.app:/cb")
	if err := e.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	local.Set("redirect_uri", "com.example.app:/cb")
	if v := view(local); v.CallbackDomain != "com.example.app:" {
		t.Fatalf("custom scheme view = %+v", v)
	}
	// An unnamed API shows its identifier; descriptions replace scope names.
	rs, _ := e.st.ResourceServers().GetByIdentifier(context.Background(), e.tenant.ID, "https://api.acme.test")
	rs.Name = ""
	rs.Scopes = []store.Scope{{Value: "read:things", Description: "Read your things"}}
	if err := e.st.ResourceServers().Update(context.Background(), rs); err != nil {
		t.Fatal(err)
	}
	e.tenant.UseScopeDescriptionsForConsent = true
	v = view(partnerQuery())
	if v.APIName != "https://api.acme.test" || strings.Join(v.Scopes, ",") != "Read your things" {
		t.Fatalf("described view = %+v", v)
	}
}

func (e *env) consentFor(t *testing.T, q url.Values, boundTo string) *store.AuthTransaction {
	t.Helper()
	txn := e.txnFor(t, q, true)
	txn.Params[sessionKey] = boundTo
	return txn
}

func TestConsentMaxAgeZeroDoesNotLoop(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	q := partnerQuery()
	q.Set("max_age", "0")
	txn := e.consentFor(t, q, e.session(t, ck).ID)
	loc := location(t, e.consent(t, txn, ck, true))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s, want a code", loc)
	}
}

func TestConsentShortMaxAgeElapsedDoesNotLoop(t *testing.T) {
	e := newEnv(t)
	ck := e.login(t, fixedNow())
	q := partnerQuery()
	q.Set("max_age", "1")
	txn := e.consentFor(t, q, e.session(t, ck).ID)
	e.h.Now = func() time.Time { return fixedNow().Add(time.Minute) }
	loc := location(t, e.consent(t, txn, ck, true))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s, want a code", loc)
	}
}

func TestConsentFromAnotherSessionRestartsLogin(t *testing.T) {
	e := newEnv(t)
	first := e.session(t, e.login(t, fixedNow()))
	second := e.login(t, fixedNow())
	txn := e.consentFor(t, partnerQuery(), first.ID)
	loc := location(t, e.consent(t, txn, second, true))
	if loc.Path != "/u/login" || loc.Query().Get("code") != "" {
		t.Fatalf("Location = %s, want the login page", loc)
	}
	if g := e.userGrant(t, "partner", "https://api.acme.test"); g != nil {
		t.Fatalf("grant stored: %v", g)
	}
}
