package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// recorder is a Mailer that keeps what it is asked to send.
type recorder struct {
	mu   sync.Mutex
	sent []email.Message
}

func (r *recorder) Send(_ context.Context, m email.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, m)
	return nil
}

var resetLinkPattern = regexp.MustCompile(`/u/reset-password\?ticket=([A-Za-z0-9]{43})`)

// resetLink returns the ticket from the most recent email.
func resetLink(t *testing.T, e *env) string {
	t.Helper()
	if len(e.mail.sent) == 0 {
		t.Fatal("no email sent")
	}
	m := resetLinkPattern.FindStringSubmatch(e.mail.sent[len(e.mail.sent)-1].Text)
	if m == nil {
		t.Fatalf("no reset link in %q", e.mail.sent[len(e.mail.sent)-1].Text)
	}
	return m[1]
}

var nonceValue = regexp.MustCompile(`nonce="[^"]*"|'nonce-[^']*'`)

// usedLinkPage reports whether body is U6's used-link page: its title and
// its text, with the quotes as html/template escapes them.
func usedLinkPage(body string) bool {
	return strings.Contains(body, "Invalid Link") &&
		strings.Contains(body, "This link has already been used. To reset your password, return to the login page and select &#34;Forgot Your Password&#34; to send a new email.")
}

func stripNonce(s string) string { return nonceValue.ReplaceAllString(s, "") }

func (e *env) conn(t *testing.T) *store.Connection {
	t.Helper()
	c, err := e.st.Connections().GetByName(context.Background(), mustTenant(t, e, "acme").ID, "Username-Password-Authentication")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) user(t *testing.T, login string) *store.User {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), mustTenant(t, e, "acme").ID, "Username-Password-Authentication", login)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// signedInElsewhere gives the user a session in another browser and a
// refresh token.
func (e *env) signedInElsewhere(t *testing.T, login string) (*http.Cookie, *store.RefreshToken) {
	t.Helper()
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u := e.user(t, login)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://acme.example.test/", nil)
	sess, err := e.h.Sessions.Start(ctx, rec, r, tn, u.UserID, "Username-Password-Authentication", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	rt := &store.RefreshToken{
		TenantID: tn.ID, ID: "rt_" + secrets.RandomString(16), TokenHash: secrets.HashToken(secrets.RandomString(43)),
		FamilyID: "fam_" + secrets.RandomString(16), ClientID: "spa", UserID: u.UserID, SessionID: sess.ID,
		Scopes: []string{"openid", "offline_access"}, AuthTime: fixedNow(), CreatedAt: fixedNow(),
	}
	if err := e.st.RefreshTokens().Create(ctx, rt); err != nil {
		t.Fatal(err)
	}
	return cookie, rt
}

func (e *env) sessionAlive(t *testing.T, c *http.Cookie) bool {
	t.Helper()
	_, err := e.st.Sessions().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, secrets.HashToken(c.Value))
	return err == nil
}

// issueTicket stores a reset ticket for the user that expires lifetime
// after fixedNow and returns its token.
func (e *env) issueTicket(t *testing.T, login string, lifetime time.Duration) string {
	t.Helper()
	raw := secrets.RandomString(43)
	tk := &store.PasswordResetTicket{
		TenantID: mustTenant(t, e, "acme").ID, ID: "prt_" + secrets.RandomString(24), TokenHash: secrets.HashToken(raw),
		UserID: e.user(t, login).UserID, Connection: "Username-Password-Authentication", ClientID: "spa", Lang: "en",
		ExpiresAt: fixedNow().Add(lifetime), CreatedAt: fixedNow().Add(-2 * time.Hour),
	}
	if err := e.st.PasswordResetTickets().Create(context.Background(), tk); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestForgotPasswordFlow(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	rec, state, csrf := b.begin(t, "ui_locales", "fr")
	if !strings.Contains(rec.Body.String(), "/u/reset-password/request?state=") {
		t.Fatal("login page lacks the forgot-password link")
	}
	// An unknown and a known address get the same page.
	unknown := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"nobody@acme.test"}})
	known := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"alice@acme.test"}})
	if unknown.Code != 200 || known.Code != 200 || stripNonce(unknown.Body.String()) != stripNonce(known.Body.String()) {
		t.Fatalf("responses differ: %d / %d", unknown.Code, known.Code)
	}
	if len(e.mail.sent) != 1 {
		t.Fatalf("sent %d emails, want 1", len(e.mail.sent))
	}
	ticket := resetLink(t, e)

	// The user also has a session and a refresh token that the reset must end.
	sessionCookie, rt := e.signedInElsewhere(t, "alice@acme.test")

	rec = b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("reset form = %d %s", rec.Code, rec.Body)
	}
	post := func(pw, confirm string) *httptest.ResponseRecorder {
		return b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {ticket}, "csrf": {m[1]}, "password": {pw}, "password_confirm": {confirm}})
	}
	if rec := post("new password 123", "different 123"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "do not match") {
		t.Fatalf("mismatch = %d", rec.Code)
	}
	if rec := post("short", "short"); rec.Code != 400 {
		t.Fatalf("weak password = %d", rec.Code)
	}
	b.cookies[session.CookieName] = sessionCookie // this browser is signed in too
	if rec := post("new password 123", "new password 123"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if b.cookies[session.CookieName] != nil || b.cookies["za_reset"] != nil {
		t.Fatal("session or reset cookie not cleared")
	}
	// Logged out everywhere: the old session and refresh token are gone.
	if e.sessionAlive(t, sessionCookie) {
		t.Fatal("session survived the reset")
	}
	if got, _ := e.st.RefreshTokens().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, rt.TokenHash); got.RevokedAt == nil {
		t.Fatal("refresh token survived the reset")
	}
	// The ticket cannot be used again.
	if rec := post("another password 1", "another password 1"); rec.Code != 400 || !usedLinkPage(rec.Body.String()) {
		t.Fatalf("replay = %d %s", rec.Code, rec.Body)
	}
	// The new password works; the old one does not.
	u, err := e.h.Database.Login(context.Background(), e.conn(t), "alice@acme.test", "new password 123")
	if err != nil || u == nil {
		t.Fatalf("new password login: %v", err)
	}
	if _, err := e.h.Database.Login(context.Background(), e.conn(t), "alice@acme.test", "alice password 1"); err == nil {
		t.Fatal("old password still works")
	}
}

func TestResetErrors(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	if rec := b.do(t, "GET", "/u/reset-password?ticket=nope", nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Link Expired") {
		t.Fatalf("unknown ticket = %d", rec.Code)
	}
	ticket := e.issueTicket(t, "alice@acme.test", -time.Minute) // already expired
	if rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Link Expired") {
		t.Fatalf("expired ticket = %d", rec.Code)
	}
	live := e.issueTicket(t, "alice@acme.test", time.Hour)
	rec := b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {live}, "csrf": {"forged"}, "password": {"new password 123"}, "password_confirm": {"new password 123"}})
	if rec.Code != 400 {
		t.Fatalf("forged csrf = %d", rec.Code)
	}
	if _, err := e.h.Database.Login(context.Background(), e.conn(t), "alice@acme.test", "alice password 1"); err != nil {
		t.Fatalf("password changed by a forged request: %v", err)
	}
}

func TestResetCookieAndPages(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	ticket := e.issueTicket(t, "alice@acme.test", time.Hour)
	rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "za_reset" {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/u/reset-password" || ck.MaxAge != 900 {
		t.Fatalf("za_reset cookie = %+v", ck)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") || !strings.Contains(csp, "'nonce-") {
		t.Fatalf("csp = %q", csp)
	}
	// Viewing the form does not use the ticket.
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, secrets.HashToken(ticket))
	if err != nil || tk.UsedAt != nil {
		t.Fatalf("ticket = %+v, %v", tk, err)
	}

	// The request page needs a valid transaction.
	if rec := b.do(t, "GET", "/u/reset-password/request?state=nope", nil); rec.Code != 400 {
		t.Fatalf("request page without transaction = %d", rec.Code)
	}
	_, state, csrf := b.begin(t)
	rec = b.do(t, "GET", "/u/reset-password/request?"+url.Values{"state": {state}}.Encode(), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="/u/reset-password/request"`) ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "form-action 'self' https://app.acme.test;") {
		t.Fatalf("request page = %d %s %s", rec.Code, rec.Header().Get("Content-Security-Policy"), rec.Body)
	}
	// A forged CSRF token sends nothing.
	if rec := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {"forged"}, "email": {"alice@acme.test"}}); rec.Code != 400 {
		t.Fatalf("forged request = %d", rec.Code)
	}
	// A blocked user gets the same page and no email.
	if rec := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"carol@acme.test"}}); rec.Code != 200 {
		t.Fatalf("blocked user = %d", rec.Code)
	}
	if len(e.mail.sent) != 0 {
		t.Fatalf("sent %d emails", len(e.mail.sent))
	}
}

func TestResetRequestSendLimit(t *testing.T) {
	e := newEnv(t)
	e.h.Resets.SendThrottle = identity.NewThrottle(2, time.Hour, time.Hour)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	for range 3 {
		if rec := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"alice@acme.test"}}); rec.Code != 200 {
			t.Fatalf("request = %d", rec.Code)
		}
	}
	if len(e.mail.sent) != 2 {
		t.Fatalf("sent %d emails, want 2", len(e.mail.sent))
	}
}

// The form asks for an email address; a username does not match.
func TestResetRequestUsernameSendsNothing(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	if rec := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"alice1"}}); rec.Code != 200 {
		t.Fatalf("request = %d", rec.Code)
	}
	if len(e.mail.sent) != 0 {
		t.Fatalf("sent %d emails for a username", len(e.mail.sent))
	}
}

// The forgot-password form counts against the per-IP limit; once it is
// reached the form is shown again with 429, whatever the address.
func TestResetRequestIPThrottle(t *testing.T) {
	e := newEnv(t)
	e.h.IPThrottle = identity.NewThrottle(2, 15*time.Minute, 15*time.Minute)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	var rec *httptest.ResponseRecorder
	for _, addr := range []string{"nobody@acme.test", "nobody2@acme.test", "alice@acme.test"} {
		rec = b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {addr}})
	}
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Too many attempts") ||
		!strings.Contains(rec.Body.String(), `action="/u/reset-password/request"`) {
		t.Fatalf("third request = %d %s", rec.Code, rec.Body)
	}
	if len(e.mail.sent) != 0 {
		t.Fatalf("sent %d emails while throttled", len(e.mail.sent))
	}
}

// completeReset opens the reset link in b and submits the new password.
func completeReset(t *testing.T, b *browser, ticket, pw string) *httptest.ResponseRecorder {
	t.Helper()
	rec := b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
	m := csrfField.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("reset form = %d %s", rec.Code, rec.Body)
	}
	return b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {ticket}, "csrf": {m[1]}, "password": {pw}, "password_confirm": {pw}})
}

// completeResetSpent posts the new-password form for a ticket whose form
// was opened before the ticket was used.
func completeResetSpent(t *testing.T, b *browser, ticket, pw string) *httptest.ResponseRecorder {
	t.Helper()
	b.do(t, "GET", "/u/reset-password?ticket="+ticket, nil)
	c, ok := b.cookies[resetCookie]
	if !ok {
		t.Fatal("no reset cookie")
	}
	return b.do(t, "POST", "/u/reset-password", url.Values{"ticket": {ticket}, "csrf": {c.Value}, "password": {pw}, "password_confirm": {pw}})
}

// A completed reset invalidates the user's other outstanding links.
func TestResetInvalidatesOtherTickets(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	first := e.issueTicket(t, "alice@acme.test", time.Hour)
	second := e.issueTicket(t, "alice@acme.test", time.Hour)
	if rec := completeReset(t, b, first, "new password 123"); rec.Code != 200 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if rec := b.do(t, "GET", "/u/reset-password?ticket="+second, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Link Expired") {
		t.Fatalf("second ticket after reset = %d %s", rec.Code, rec.Body)
	}
}

// A completed reset clears a brute-force lock on the user's email and
// username, as Auth0 unblocks a user whose password is changed.
func TestResetClearsLoginLock(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	login := func(user, pw string) int {
		return b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {user}, "password": {pw}}).Code
	}
	for _, user := range []string{"alice@acme.test", "alice1"} {
		for range 3 {
			login(user, "wrong")
		}
		if code := login(user, "alice password 1"); code != http.StatusTooManyRequests {
			t.Fatalf("%s not locked: %d", user, code)
		}
	}
	if rec := completeReset(t, e.browser("acme.example.test"), e.issueTicket(t, "alice@acme.test", time.Hour), "new password 123"); rec.Code != 200 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	for _, user := range []string{"alice@acme.test", "alice1"} {
		b = e.browser("acme.example.test") // not yet signed in
		_, state, csrf = b.begin(t)
		if code := login(user, "new password 123"); code != http.StatusFound {
			t.Fatalf("login as %s after reset = %d", user, code)
		}
	}
}

// A user blocked after the link was sent cannot use it, and the ticket is
// not spent.
func TestResetBlockedAfterIssue(t *testing.T) {
	e := newEnv(t)
	ticket := e.issueTicket(t, "alice@acme.test", time.Hour)
	u := e.user(t, "alice@acme.test")
	u.Blocked = true
	if err := e.st.Users().Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if rec := completeReset(t, e.browser("acme.example.test"), ticket, "new password 123"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Link Expired") {
		t.Fatalf("reset for blocked user = %d %s", rec.Code, rec.Body)
	}
	tk, err := e.st.PasswordResetTickets().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, secrets.HashToken(ticket))
	if err != nil || tk.UsedAt != nil {
		t.Fatalf("ticket = %+v, %v", tk, err)
	}
	u.Blocked = false
	if err := e.st.Users().Update(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := e.h.Database.Login(context.Background(), e.conn(t), "alice@acme.test", "alice password 1"); err != nil {
		t.Fatalf("password changed for a blocked user: %v", err)
	}
}

func TestLoginPageWithoutResets(t *testing.T) {
	e := newEnv(t)
	e.h.Resets = nil
	rec, _, _ := e.browser("acme.example.test").begin(t)
	if strings.Contains(rec.Body.String(), "/u/reset-password/request") {
		t.Fatal("forgot-password link shown without reset support")
	}
}

// legacyResetEnv serves a legacy user, dave@legacy.test (user_id 42), known
// only to the get_user script. changed is what change_password returns;
// pw records the password it was given.
type legacyResetEnv struct {
	*env
	changed  any
	fail     error
	lastArgs []any
}

func newLegacyResetEnv(t *testing.T) *legacyResetEnv {
	t.Helper()
	le := &legacyResetEnv{env: newEnv(t), changed: true}
	le.scripts.Funcs[store.ScriptGetUser] = func(args []any) (any, error) {
		if args[0] == "dave@legacy.test" {
			return map[string]any{"user_id": 42, "email": "dave@legacy.test"}, nil
		}
		return nil, nil
	}
	le.scripts.Funcs[store.ScriptChangePassword] = func(args []any) (any, error) {
		le.lastArgs = args
		return le.changed, le.fail
	}
	return le
}

// requestLegacyReset asks for a reset link on the hosted page and returns
// the ticket from the email.
func (le *legacyResetEnv) requestLegacyReset(t *testing.T, b *browser) string {
	t.Helper()
	state, csrf := b.legacyBegin(t)
	rec := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"Dave@legacy.test"}})
	if rec.Code != 200 {
		t.Fatalf("reset request = %d %s", rec.Code, rec.Body)
	}
	return resetLink(t, le.env)
}

func TestLegacyResetCallsChangePassword(t *testing.T) {
	le := newLegacyResetEnv(t)
	b := le.browser("acme.example.test")
	ticket := le.requestLegacyReset(t, b)
	ctx := context.Background()
	tn := mustTenant(t, le.env, "acme")
	sess, err := le.h.Sessions.Start(ctx, httptest.NewRecorder(), httptest.NewRequest("GET", "https://acme.example.test/", nil),
		tn, "auth0|42", "Legacy-DB", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if rec := completeReset(t, b, ticket, "new legacy pw 1"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if len(le.lastArgs) != 2 || le.lastArgs[0] != "dave@legacy.test" || le.lastArgs[1] != "new legacy pw 1" {
		t.Fatalf("change_password args = %v", le.lastArgs)
	}
	if _, err := le.st.Sessions().GetByTokenHash(ctx, tn.ID, sess.TokenHash); err == nil {
		t.Fatal("session survived the reset")
	}
	u, err := le.st.Users().Get(ctx, tn.ID, "auth0|42")
	if err != nil || u.Identities[0].PasswordHash != "" {
		t.Fatalf("local user = %+v, %v", u, err)
	}
}

// change_password runs after the ticket is used, so a refusal or failure
// spends the link (two submits must not run the script twice); a retry
// gets the used-link page.
func TestLegacyResetNotChangedSpendsTicket(t *testing.T) {
	le := newLegacyResetEnv(t)
	le.changed = false
	b := le.browser("acme.example.test")
	ticket := le.requestLegacyReset(t, b)
	if rec := completeReset(t, b, ticket, "new legacy pw 1"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "could not be changed") {
		t.Fatalf("not changed = %d %s", rec.Code, rec.Body)
	}
	le.changed = true
	if rec := completeResetSpent(t, b, ticket, "new legacy pw 1"); rec.Code != 400 || !usedLinkPage(rec.Body.String()) {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
}

func TestLegacyResetUnauthorizedSpendsTicket(t *testing.T) {
	le := newLegacyResetEnv(t)
	le.fail = &customdb.ScriptError{Kind: customdb.KindUnauthorized, Message: "<i>locked</i>"}
	b := le.browser("acme.example.test")
	ticket := le.requestLegacyReset(t, b)
	rec := completeReset(t, b, ticket, "new legacy pw 1")
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "&lt;i&gt;locked&lt;/i&gt;") {
		t.Fatalf("unauthorized = %d %s", rec.Code, rec.Body)
	}
	le.fail = nil
	if rec := completeResetSpent(t, b, ticket, "new legacy pw 1"); rec.Code != 400 || !usedLinkPage(rec.Body.String()) {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
}

func TestLegacyResetScriptErrorSpendsTicket(t *testing.T) {
	le := newLegacyResetEnv(t)
	le.fail = customdb.ErrTimeout
	b := le.browser("acme.example.test")
	ticket := le.requestLegacyReset(t, b)
	if rec := completeReset(t, b, ticket, "new legacy pw 1"); rec.Code != 500 {
		t.Fatalf("script error = %d %s", rec.Code, rec.Body)
	}
	le.fail = nil
	if rec := completeResetSpent(t, b, ticket, "new legacy pw 1"); rec.Code != 400 || !usedLinkPage(rec.Body.String()) {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
}

// A failing get_user gets the same page and sends nothing.
func TestLegacyResetRequestScriptError(t *testing.T) {
	le := newLegacyResetEnv(t)
	le.scripts.Funcs[store.ScriptGetUser] = func([]any) (any, error) { return nil, customdb.ErrUnavailable }
	b := le.browser("acme.example.test")
	state, csrf := b.legacyBegin(t)
	rec := b.do(t, "POST", "/u/reset-password/request", url.Values{"state": {state}, "csrf": {csrf}, "email": {"dave@legacy.test"}})
	if rec.Code != 200 || len(le.mail.sent) != 0 {
		t.Fatalf("got %d, sent %d", rec.Code, len(le.mail.sent))
	}
	// Logged once, by identity.
	if logs := le.logs.String(); strings.Count(logs, "custom database script failed") != 1 || strings.Contains(logs, "reset request: find user") {
		t.Fatalf("logs:\n%s", logs)
	}
}

// In import mode a hosted reset of a user known only to the legacy store
// migrates the user: the new password is stored locally, change_password
// never runs, and the next login does not call the login script.
func TestImportResetMigrates(t *testing.T) {
	le := newLegacyResetEnv(t)
	le.useImportMode(t)
	le.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
		t.Error("login script called after the reset")
		return nil, &customdb.ScriptError{Kind: customdb.KindWrongCredentials}
	}
	b := le.browser("acme.example.test")
	ticket := le.requestLegacyReset(t, b)
	if rec := completeReset(t, b, ticket, "new import pw 1"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if le.lastArgs != nil {
		t.Fatalf("change_password ran: %v", le.lastArgs)
	}
	u, err := le.st.Users().Get(context.Background(), mustTenant(t, le.env, "acme").ID, "auth0|42")
	if err != nil || u.Identities[0].PasswordHash == "" {
		t.Fatalf("local user = %+v, %v", u, err)
	}
	b = le.browser("acme.example.test")
	state, csrf := b.legacyBegin(t)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"dave@legacy.test"}, "password": {"new import pw 1"}})
	if rec.Code != 302 {
		t.Fatalf("login with the new password = %d %s", rec.Code, rec.Body)
	}
}

// A connection with brute-force protection off is not throttled.
func TestLoginThrottleOffWithoutBruteForceProtection(t *testing.T) {
	e := newEnv(t)
	c := e.conn(t)
	if !c.BruteForceProtection {
		t.Fatal("the seeded connection must have brute-force protection on")
	}
	c.BruteForceProtection = false
	if err := e.st.Connections().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	login := func(pw string) int {
		return b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}, "password": {pw}}).Code
	}
	for range 6 {
		login("wrong")
	}
	if code := login("alice password 1"); code != http.StatusFound {
		t.Fatalf("login after 6 failures with protection off = %d", code)
	}
}

// A password used recently is refused by signup and by reset, and a reset
// records the new password in the history.
func TestResetRefusesHistoryAndPersonalData(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := e.conn(t)
	c.PasswordOptions.History = store.PasswordHistory{Active: true, Size: 2}
	c.PasswordOptions.ProfileData = store.PasswordProfileData{Active: true, BlockedFields: []string{"username"}}
	if err := e.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	reset := func(pw string) *httptest.ResponseRecorder {
		return completeReset(t, b, e.issueTicket(t, "alice@acme.test", time.Hour), pw)
	}
	if rec := reset("xx-alice1-xx"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Password must not contain personal information.") {
		t.Fatalf("personal data = %d %s", rec.Code, rec.Body)
	}
	for _, pw := range []string{"first new password", "second new password"} {
		if rec := reset(pw); rec.Code != 200 {
			t.Fatalf("reset to %q = %d %s", pw, rec.Code, rec.Body)
		}
	}
	for _, pw := range []string{"first new password", "second new password"} {
		if rec := reset(pw); rec.Code != 400 || !strings.Contains(rec.Body.String(), "Password was used recently.") {
			t.Fatalf("reuse of %q = %d %s", pw, rec.Code, rec.Body)
		}
	}
	// A third password pushes the first out of a history of two.
	if rec := reset("third new password"); rec.Code != 200 {
		t.Fatalf("third = %d %s", rec.Code, rec.Body)
	}
	if rec := reset("first new password"); rec.Code != 200 {
		t.Fatalf("a password older than the history size = %d %s", rec.Code, rec.Body)
	}
	hist, _ := e.st.PasswordHistories().List(ctx, c.TenantID, e.user(t, "alice@acme.test").UserID)
	if len(hist) != 2 {
		t.Fatalf("stored history = %d, want 2", len(hist))
	}
}
