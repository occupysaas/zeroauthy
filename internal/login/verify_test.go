package login

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/dbconn"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// issueVerification stores an email verification ticket for the user that
// expires lifetime after fixedNow and returns its token.
func (e *env) issueVerification(t *testing.T, userID, connection, resultURL string, includeEmail bool, lang string, lifetime time.Duration) string {
	t.Helper()
	u, err := e.st.Users().Get(context.Background(), mustTenant(t, e, "acme").ID, userID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dbconn.IssueVerificationTicket(context.Background(), e.st, store.EmailVerificationTicket{
		TenantID: mustTenant(t, e, "acme").ID, UserID: userID, Connection: connection, Email: strings.ToLower(u.Email),
		ResultURL: resultURL, IncludeEmailInRedirect: includeEmail, Lang: lang,
	}, fixedNow(), lifetime)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type ticketCountStore struct {
	store.Store
	creates int
}
type ticketCountRepo struct {
	store.EmailVerificationTickets
	owner *ticketCountStore
}

func (s *ticketCountStore) EmailVerificationTickets() store.EmailVerificationTickets {
	return ticketCountRepo{EmailVerificationTickets: s.Store.EmailVerificationTickets(), owner: s}
}
func (r ticketCountRepo) Create(ctx context.Context, t *store.EmailVerificationTicket) error {
	r.owner.creates++
	return r.EmailVerificationTickets.Create(ctx, t)
}

func TestEmailTemplateTicketPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u := e.user(t, "alice@acme.test")
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	renderer, _ := email.NewRenderer()
	svc := &email.Service{Store: e.st, Wrapper: w, Renderer: renderer, Providers: &providers.Factory{}, Fallback: e.mail, DefaultFrom: "zeroauthy@example.test", Now: fixedNow}
	counted := &ticketCountStore{Store: e.st}
	mailer := &VerificationMailer{Store: counted, Mailer: e.mail, Email: svc, Now: fixedNow}
	res := tenant.Resolved{Tenant: tn, Host: "acme.example.test"}
	put := func(seconds int64, enabled bool, result string) {
		fields := map[string]any{"body": "<a href=\"{{ url }}\">verify</a>", "subject": "Verify", "enabled": enabled, "syntax": "liquid", "urlLifetimeInSeconds": seconds, "resultUrl": result, "includeEmailInRedirect": true}
		old, err := e.st.EmailTemplates().Get(ctx, tn.ID, "verify_email")
		expected := int64(0)
		if err == nil {
			expected = old.Revision
		}
		if err := e.st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: tn.ID, Name: "verify_email", Fields: fields}, expected); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		seconds int64
		want    time.Duration
	}{{0, dbconn.VerificationTicketLifetime}, {604800, 604800 * time.Second}} {
		put(tc.seconds, true, "https://app.acme.test/cb")
		if err := mailer.Send(ctx, res, u, "spa", "en"); err != nil {
			t.Fatalf("lifetime %d: %v", tc.seconds, err)
		}
		if len(e.mail.sent) == 0 {
			t.Fatal("custom verification email missing")
		}
		match := regexp.MustCompile(`ticket=([A-Za-z0-9]+)`).FindStringSubmatch(e.mail.sent[len(e.mail.sent)-1].HTML)
		if len(match) < 2 {
			t.Fatalf("missing ticket in message: %s", e.mail.sent[len(e.mail.sent)-1].Text)
		}
		ticket := match[1]
		row, err := e.st.EmailVerificationTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(ticket))
		if err != nil {
			t.Fatal(err)
		}
		if got := row.ExpiresAt.Sub(fixedNow()); got != tc.want {
			t.Fatalf("lifetime=%s want %s", got, tc.want)
		}
		if row.ClientID != "spa" || row.ResultURL != "https://app.acme.test/cb" || !row.IncludeEmailInRedirect {
			t.Fatalf("ticket policy fields: %+v", row)
		}
	}
	before := counted.creates
	for _, tc := range []struct {
		seconds int64
		url     string
	}{{604801, "https://app.acme.test/cb"}, {0, "https://evil.example/cb"}, {0, "https://app.acme.test/cb-evil"}, {0, "{{ user.app_metadata.redirect }}"}} {
		put(tc.seconds, true, tc.url)
		if err := mailer.Send(ctx, res, u, "spa", "en"); err == nil {
			t.Errorf("unsafe template policy accepted: %d %q", tc.seconds, tc.url)
		}
	}
	if counted.creates != before {
		t.Fatal("rejected policy created a ticket")
	}
	put(0, false, "https://app.acme.test/cb")
	count := len(e.mail.sent)
	if err := mailer.Send(ctx, res, u, "spa", "en"); err != nil {
		t.Fatal(err)
	}
	if counted.creates != before || len(e.mail.sent) != count {
		t.Fatal("disabled template created a ticket or sent mail")
	}
}

func welcomeService(t *testing.T, e *env) *email.Service {
	t.Helper()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	renderer, _ := email.NewRenderer()
	svc := &email.Service{Store: e.st, Wrapper: w, Renderer: renderer, Providers: &providers.Factory{}, Fallback: e.mail, DefaultFrom: "zeroauthy@example.test", Now: fixedNow}
	tn := mustTenant(t, e, "acme")
	if err := e.st.EmailTemplates().Put(context.Background(), &store.EmailTemplate{TenantID: tn.ID, Name: "welcome_email", Fields: map[string]any{"body": "<p>Welcome {{ user.email | escape }}</p>", "subject": "Welcome to {{ tenant.name }}", "enabled": true, "syntax": "liquid"}}, 0); err != nil {
		t.Fatal(err)
	}
	e.h.Verification.Email = svc
	e.h.Verification.Mailer = e.mail
	e.h.Verification.Go = func(f func()) { f() }
	return svc
}

func TestWelcomeAfterVerification(t *testing.T) {
	e := newEnv(t)
	welcomeService(t, e)
	u := e.user(t, "alice@acme.test")
	ticket := e.issueVerification(t, u.UserID, "Username-Password-Authentication", "", false, "en", time.Hour)
	b := e.browser("acme.example.test")
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 200 || !e.verified(t, u.UserID) {
		t.Fatalf("verify=%d verified=%v", rec.Code, e.verified(t, u.UserID))
	}
	if len(e.mail.sent) != 1 || e.mail.sent[0].Subject != "Welcome to acme" || !strings.Contains(e.mail.sent[0].Text, u.Email) {
		t.Fatalf("welcome after verify: %+v", e.mail.sent)
	}
	b.do(t, "GET", verifyPath+ticket, nil)
	if len(e.mail.sent) != 1 {
		t.Fatalf("verification replay sent another welcome: %d", len(e.mail.sent))
	}
}

func TestWelcomeSignupBothPaths(t *testing.T) {
	e := newEnv(t)
	welcomeService(t, e)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"hosted@acme.test"}, "password": {"hosted good password 1"}})
	if rec.Code != 302 || len(e.mail.sent) != 1 {
		t.Fatalf("hosted signup=%d emails=%+v", rec.Code, e.mail.sent)
	}
	link := verifyLinkPattern.FindStringSubmatch(e.mail.sent[0].Text)
	if len(link) != 2 {
		t.Fatalf("hosted verification message=%+v", e.mail.sent[0])
	}
	if rec = b.do(t, "GET", verifyPath+link[1], nil); rec.Code != 200 || len(e.mail.sent) != 2 || e.mail.sent[1].To != "hosted@acme.test" {
		t.Fatalf("hosted verify=%d emails=%+v", rec.Code, e.mail.sent)
	}
	api := &dbconn.Handlers{Store: e.st, Database: e.h.Database, Verification: e.h.Verification, Now: fixedNow, Go: func(f func()) { f() }}
	body := `{"client_id":"spa","connection":"Username-Password-Authentication","email":"api@acme.test","password":"api good password 1"}`
	req := httptest.NewRequest("POST", "https://acme.example.test/dbconnections/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	wrapped := tenant.NewResolver(e.st.Tenants(), "", false).Middleware(http.HandlerFunc(api.Signup))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != 200 || len(e.mail.sent) != 3 {
		t.Fatalf("API signup=%d %s emails=%+v", rr.Code, rr.Body, e.mail.sent)
	}
	link = verifyLinkPattern.FindStringSubmatch(e.mail.sent[2].Text)
	if len(link) != 2 {
		t.Fatalf("API verification message=%+v", e.mail.sent[2])
	}
	if rec = b.do(t, "GET", verifyPath+link[1], nil); rec.Code != 200 || len(e.mail.sent) != 4 || e.mail.sent[3].To != "api@acme.test" {
		t.Fatalf("API verify=%d emails=%+v", rec.Code, e.mail.sent)
	}
}

type failingWelcomeMailer struct{}

func (failingWelcomeMailer) Send(context.Context, email.Message) error {
	return errors.New("send failed")
}

func TestWelcomeSendFailureDoesNotUndoVerification(t *testing.T) {
	e := newEnv(t)
	svc := welcomeService(t, e)
	svc.Fallback = failingWelcomeMailer{}
	e.h.Verification.Mailer = failingWelcomeMailer{}
	u := e.user(t, "alice@acme.test")
	ticket := e.issueVerification(t, u.UserID, "Username-Password-Authentication", "", false, "en", time.Hour)
	b := e.browser("acme.example.test")
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 200 || !e.verified(t, u.UserID) {
		t.Fatalf("mail failure reversed verification: %d verified=%v", rec.Code, e.verified(t, u.UserID))
	}
}

func (e *env) verified(t *testing.T, userID string) bool {
	t.Helper()
	u, err := e.st.Users().Get(context.Background(), mustTenant(t, e, "acme").ID, userID)
	if err != nil {
		t.Fatal(err)
	}
	return u.EmailVerified
}

const verifyPath = "/u/email-verification?ticket="

// Opening the link verifies at once (no button); without a result_url the
// page says so, and a second open or an unknown ticket shows the error.
func TestEmailVerificationPage(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	alice := e.user(t, "alice@acme.test")
	if alice.EmailVerified {
		t.Fatal("alice starts verified")
	}
	ticket := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", "", false, "", time.Hour)
	rec := b.do(t, "GET", verifyPath+ticket, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Email Verified") ||
		!strings.Contains(rec.Body.String(), "Your email address was successfully verified.") {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	if !e.verified(t, alice.UserID) {
		t.Fatal("email_verified not set")
	}
	tk, err := e.st.EmailVerificationTickets().GetByTokenHash(context.Background(), mustTenant(t, e, "acme").ID, secrets.HashToken(ticket))
	if err != nil || tk.UsedAt == nil {
		t.Fatalf("ticket not used: %+v %v", tk, err)
	}
	for _, path := range []string{verifyPath + ticket, verifyPath + "nope", "/u/email-verification"} {
		rec := b.do(t, "GET", path, nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), ">Error<") ||
			!strings.Contains(rec.Body.String(), "Your email address could not be verified.") {
			t.Fatalf("%s = %d %s", path, rec.Code, rec.Body)
		}
	}
	// A new ticket for a verified user.
	again := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", "", false, "", time.Hour)
	if rec := b.do(t, "GET", verifyPath+again, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), "This account is already verified.") {
		t.Fatalf("already verified = %d %s", rec.Code, rec.Body)
	}
}

// A used and an expired ticket show the error page in the ticket's
// language; an expired one verifies nothing.
func TestEmailVerificationErrorsLocalized(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	alice := e.user(t, "alice@acme.test")
	expired := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", "https://app.acme.test/done", true, "fr", -time.Minute)
	rec := b.do(t, "GET", verifyPath+expired, nil)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `lang="fr"`) || !strings.Contains(rec.Body.String(), "could not be verified") {
		t.Fatalf("expired = %d %s", rec.Code, rec.Body)
	}
	if e.verified(t, alice.UserID) {
		t.Fatal("an expired ticket verified the email")
	}
	used := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", "", false, "fr", time.Hour)
	if rec := b.do(t, "GET", verifyPath+used, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("first use = %d %s", rec.Code, rec.Body)
	}
	if rec := b.do(t, "GET", verifyPath+used, nil); rec.Code != 400 || !strings.Contains(rec.Body.String(), `lang="fr"`) {
		t.Fatalf("reuse = %d %s", rec.Code, rec.Body)
	}
}

// With a result_url the page redirects there with Auth0's parameters
// appended to the existing query (U6).
func TestEmailVerificationRedirect(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	alice := e.user(t, "alice@acme.test")
	const result = "https://app.acme.test/done?x=1#frag"
	ticket := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", result, true, "", time.Hour)
	want := map[string]string{
		"success": "https://app.acme.test/done?x=1&supportSignUp=true&supportForgotPassword=true&email=alice%40acme.test" +
			"&message=Your%20email%20was%20verified.%20You%20can%20continue%20using%20the%20application.&success=true&code=success#frag",
		"reused":  "https://app.acme.test/done?x=1&email=alice%40acme.test&message=This%20URL%20can%20be%20used%20only%20once&success=false#frag",
		"already": "https://app.acme.test/done?x=1&supportSignUp=true&supportForgotPassword=true&message=This%20account%20is%20already%20verified.&success=false&code=already-verified#frag",
	}
	rec := b.do(t, "GET", verifyPath+ticket, nil)
	if rec.Code != 302 || rec.Header().Get("Location") != want["success"] {
		t.Fatalf("success = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if !e.verified(t, alice.UserID) {
		t.Fatal("email_verified not set")
	}
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 302 || rec.Header().Get("Location") != want["reused"] {
		t.Fatalf("reused = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	again := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", result, true, "", time.Hour)
	if rec := b.do(t, "GET", verifyPath+again, nil); rec.Code != 302 || rec.Header().Get("Location") != want["already"] {
		t.Fatalf("already verified = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	// Without includeEmailInRedirect the email is left out.
	bob := e.signupUser(t, "bob@acme.test")
	plain := e.issueVerification(t, bob.UserID, "Username-Password-Authentication", "https://app.acme.test/done", false, "", time.Hour)
	rec = b.do(t, "GET", verifyPath+plain, nil)
	if loc := rec.Header().Get("Location"); rec.Code != 302 || strings.Contains(loc, "email=") || !strings.HasPrefix(loc, "https://app.acme.test/done?supportSignUp=true&") {
		t.Fatalf("no email = %d %q", rec.Code, loc)
	}
}

// signupUser creates an unverified user on the database connection.
func (e *env) signupUser(t *testing.T, email string) *store.User {
	t.Helper()
	tn := mustTenant(t, e, "acme")
	u := &store.User{TenantID: tn.ID, UserID: "auth0|" + secrets.RandomHex(12), Email: email, CreatedAt: fixedNow(), UpdatedAt: fixedNow()}
	u.Identities = []store.Identity{{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: strings.TrimPrefix(u.UserID, "auth0|")}}
	if err := e.st.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// On a custom database connection the verify script runs first; when it
// fails or answers false, email_verified stays false, the error page shows
// and the ticket still works.
func TestEmailVerificationLegacyVerify(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	tn := mustTenant(t, e, "acme")
	u := &store.User{TenantID: tn.ID, UserID: "auth0|42", Email: "dave@legacy.test", CreatedAt: fixedNow(), UpdatedAt: fixedNow(),
		Identities: []store.Identity{{Connection: "Legacy-DB", Provider: "auth0", UserID: "42"}}}
	if err := e.st.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	var result any
	var fail error
	var args []any
	e.scripts.Funcs[store.ScriptVerify] = func(a []any) (any, error) { args = a; return result, fail }
	ticket := e.issueVerification(t, u.UserID, "Legacy-DB", "https://legacy.acme.test/done", false, "", time.Hour)
	for _, c := range []struct {
		result any
		fail   error
	}{{false, nil}, {nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "db down cfg-secret-9f3a"}}} {
		result, fail = c.result, c.fail
		rec := b.do(t, "GET", verifyPath+ticket, nil)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "could not be verified") {
			t.Fatalf("verify %v/%v = %d %s", c.result, c.fail, rec.Code, rec.Body)
		}
		if e.verified(t, u.UserID) {
			t.Fatal("email_verified set although verify failed")
		}
	}
	if strings.Contains(e.logs.String(), "cfg-secret-9f3a") || strings.Contains(e.logs.String(), ticket) {
		t.Fatal("log holds a secret or the ticket")
	}
	result, fail = true, nil
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 302 {
		t.Fatalf("verify true = %d %s", rec.Code, rec.Body)
	}
	if len(args) != 1 || args[0] != "dave@legacy.test" || !e.verified(t, u.UserID) {
		t.Fatalf("args = %v, verified = %v", args, e.verified(t, u.UserID))
	}
}

var verifyLinkPattern = regexp.MustCompile(`https://acme\.example\.test/u/email-verification\?ticket=([A-Za-z0-9]{32})#`)

// Hosted signup sends one verification email, whose link verifies the
// new user.
func TestSignupSendsVerificationEmail(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup", "ui_locales", "fr")
	rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"long enough pw"}})
	if rec.Code != 302 {
		t.Fatalf("signup = %d %s", rec.Code, rec.Body)
	}
	if len(e.mail.sent) != 1 {
		t.Fatalf("sent %d emails, want 1", len(e.mail.sent))
	}
	m := e.mail.sent[0]
	link := verifyLinkPattern.FindStringSubmatch(m.Text)
	if m.To != "bob@acme.test" || link == nil || !strings.Contains(m.HTML, `lang="fr"`) {
		t.Fatalf("email = %+v", m)
	}
	bob := e.user(t, "bob@acme.test")
	tk, err := e.st.EmailVerificationTickets().GetByTokenHash(context.Background(), bob.TenantID, secrets.HashToken(link[1]))
	if err != nil || tk.ExpiresAt.Sub(fixedNow()) != 432000*time.Second || tk.ClientID != "spa" || tk.Lang != "fr" || tk.Email != "bob@acme.test" {
		t.Fatalf("ticket = %+v %v", tk, err)
	}
	if rec := b.do(t, "GET", verifyPath+link[1], nil); rec.Code != 200 || !e.verified(t, bob.UserID) {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
	// A failed signup sends nothing more.
	b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"long enough pw"}})
	if len(e.mail.sent) != 1 {
		t.Fatalf("sent %d emails after a duplicate signup", len(e.mail.sent))
	}
}

// Signup works without a mailer: nothing is sent and nothing fails.
func TestSignupWithoutMailer(t *testing.T) {
	e := newEnv(t)
	e.h.Verification.Mailer = nil
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	if rec := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"bob@acme.test"}, "password": {"long enough pw"}}); rec.Code != 302 {
		t.Fatalf("signup = %d %s", rec.Code, rec.Body)
	}
}

// SendVerification (the Management API's sender) issues a fresh ticket on
// the tenant's host and emails its link.
func TestVerificationMailerSendVerification(t *testing.T) {
	e := newEnv(t)
	alice := e.user(t, "alice@acme.test")
	if err := e.h.Verification.SendVerification(context.Background(), alice.TenantID, alice, "spa", ""); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.sent) != 1 || verifyLinkPattern.FindStringSubmatch(e.mail.sent[0].Text) == nil || e.mail.sent[0].To != "alice@acme.test" {
		t.Fatalf("sent = %+v", e.mail.sent)
	}
	// A user without an email gets nothing.
	if err := e.h.Verification.SendVerification(context.Background(), alice.TenantID, &store.User{TenantID: alice.TenantID, UserID: "auth0|x"}, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(e.mail.sent) != 1 {
		t.Fatalf("sent %d", len(e.mail.sent))
	}
}

// A password-change ticket link (/u/reset-verify) leads to the reset form;
// the success page does not redirect to result_url, mark_email_as_verified
// sets email_verified, and a reopened link shows the used page (U6).
func TestPasswordChangeTicket(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	alice := e.user(t, "alice@acme.test")
	raw, err := dbconn.IssueResetTicket(context.Background(), e.st, store.PasswordResetTicket{
		TenantID: alice.TenantID, UserID: alice.UserID, Connection: "Username-Password-Authentication",
		ResultURL: "https://app.acme.test/after", MarkEmailVerified: true,
	}, dbconn.TicketTokenLength, fixedNow(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := b.do(t, "GET", "/u/reset-verify?ticket="+raw, nil)
	if rec.Code != 302 || rec.Header().Get("Location") != "/u/reset-password?ticket="+raw {
		t.Fatalf("reset-verify = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = completeReset(t, b, raw, "new password 123")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Password changed") || rec.Header().Get("Location") != "" ||
		strings.Contains(rec.Body.String(), "app.acme.test/after") {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if !e.verified(t, alice.UserID) {
		t.Fatal("mark_email_as_verified did not set email_verified")
	}
	rec = b.do(t, "GET", "/u/reset-verify?ticket="+raw, nil)
	rec = b.do(t, "GET", rec.Header().Get("Location"), nil)
	if rec.Code != 400 || !usedLinkPage(rec.Body.String()) {
		t.Fatalf("reused = %d %s", rec.Code, rec.Body)
	}
	if rec := b.do(t, "GET", "/u/reset-password?ticket=nope", nil); rec.Code != 400 {
		t.Fatalf("unknown = %d", rec.Code)
	}

	// Without mark_email_as_verified the flag is left alone.
	bob := e.signupUser(t, "bob@acme.test")
	raw, _ = dbconn.IssueResetTicket(context.Background(), e.st, store.PasswordResetTicket{
		TenantID: bob.TenantID, UserID: bob.UserID, Connection: "Username-Password-Authentication",
	}, dbconn.TicketTokenLength, fixedNow(), time.Hour)
	if rec := completeReset(t, b, raw, "new password 456"); rec.Code != 200 {
		t.Fatalf("reset = %d %s", rec.Code, rec.Body)
	}
	if e.verified(t, bob.UserID) {
		t.Fatal("email_verified set without mark_email_as_verified")
	}
}

// A ticket verifies only the address it was issued for: after the email
// changes (here through the custom database profile sync on login), it
// verifies nothing and shows the error page, even with a result_url.
func TestEmailVerificationEmailChanged(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	u := &store.User{TenantID: tn.ID, UserID: "auth0|42", Email: "dave@legacy.test", CreatedAt: fixedNow(), UpdatedAt: fixedNow(),
		Identities: []store.Identity{{Connection: "Legacy-DB", Provider: "auth0", UserID: "42"}}}
	if err := e.st.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	e.scripts.Funcs[store.ScriptVerify] = func([]any) (any, error) { return true, nil }
	ticket := e.issueVerification(t, u.UserID, "Legacy-DB", "https://legacy.acme.test/done", true, "", time.Hour)
	e.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
		return map[string]any{"user_id": 42, "email": "dave.new@legacy.test"}, nil
	}
	conn, err := e.st.Connections().GetByName(ctx, tn.ID, "Legacy-DB")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.h.Database.Login(ctx, conn, "dave@legacy.test", "pw"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.st.Users().Get(ctx, tn.ID, u.UserID); got.Email != "dave.new@legacy.test" {
		t.Fatalf("profile sync did not change the email: %+v", got)
	}
	rec := b.do(t, "GET", verifyPath+ticket, nil)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "could not be verified") {
		t.Fatalf("changed email = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if e.verified(t, u.UserID) {
		t.Fatal("an old-address ticket verified the new address")
	}

	// The same for an email changed directly in the store.
	alice := e.user(t, "alice@acme.test")
	ticket = e.issueVerification(t, alice.UserID, "Username-Password-Authentication", "", false, "", time.Hour)
	alice.Email = "alice2@acme.test"
	if err := e.st.Users().Update(ctx, alice); err != nil {
		t.Fatal(err)
	}
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 400 || e.verified(t, alice.UserID) {
		t.Fatalf("changed email = %d %s", rec.Code, rec.Body)
	}
}

// failingUpdates is a store whose user updates fail inside transactions.
type failingUpdates struct{ store.Store }

func (s failingUpdates) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(failingUpdates{tx}) })
}

func (s failingUpdates) Users() store.Users { return failingUsers{s.Store.Users()} }

type failingUsers struct{ store.Users }

func (failingUsers) Update(context.Context, *store.User) error { return errors.New("update failed") }

// A failure setting email_verified rolls back the use of the ticket, so
// the link still works afterwards.
func TestEmailVerificationUpdateFailureKeepsTicket(t *testing.T) {
	e := newEnv(t)
	b := e.browser("acme.example.test")
	alice := e.user(t, "alice@acme.test")
	ticket := e.issueVerification(t, alice.UserID, "Username-Password-Authentication", "", false, "", time.Hour)
	e.h.Store = failingUpdates{e.st}
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 500 {
		t.Fatalf("failing update = %d %s", rec.Code, rec.Body)
	}
	tk, err := e.st.EmailVerificationTickets().GetByTokenHash(context.Background(), alice.TenantID, secrets.HashToken(ticket))
	if err != nil || tk.UsedAt != nil {
		t.Fatalf("ticket = %+v %v, want unused", tk, err)
	}
	e.h.Store = e.st
	if rec := b.do(t, "GET", verifyPath+ticket, nil); rec.Code != 200 || !e.verified(t, alice.UserID) {
		t.Fatalf("retry = %d %s", rec.Code, rec.Body)
	}
}
