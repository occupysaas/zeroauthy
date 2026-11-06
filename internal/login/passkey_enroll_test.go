package login

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

// Removing the post-MFA prompt gate makes these tests issue a code prematurely.
func enrollmentEnv(t *testing.T, existing bool) (*env, *browser, *store.User) {
	t.Helper()
	e, u, _, a := passkeyEnv(t)
	e.h.Authz.Passkeys = e.h.Passkeys
	if !existing {
		if err := e.st.MFA().DeleteAuthenticator(context.Background(), u.TenantID, u.UserID, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	old := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/u/passkey-enrollment") {
			if r.Method == "POST" {
				tenantHandler(e.h.PasskeyEnrollmentPost, e.st).ServeHTTP(w, r)
			} else {
				tenantHandler(e.h.PasskeyEnrollmentPage, e.st).ServeHTTP(w, r)
			}
			return
		}
		old.ServeHTTP(w, r)
	})
	return e, e.browser("acme.example.test"), u
}
func passwordEnrollment(t *testing.T, b *browser, extra ...string) string {
	t.Helper()
	_, state, csrf := b.begin(t, extra...)
	rec := b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {"alice@acme.test"}})
	if !strings.Contains(rec.Header().Get("Location"), "/u/login/password") {
		t.Fatalf("identifier: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	page := b.do(t, "GET", rec.Header().Get("Location"), nil)
	csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	rec = b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "password": {"alice password 1"}})
	return rec.Header().Get("Location")
}
func TestProgressiveEnrollmentOffered(t *testing.T) {
	for _, snooze := range []bool{false, true} {
		t.Run(map[bool]string{false: "skip", true: "snooze"}[snooze], func(t *testing.T) {
			e, b, u := enrollmentEnv(t, false)
			loc := passwordEnrollment(t, b)
			if !strings.HasPrefix(loc, "/u/passkey-enrollment?") {
				t.Fatalf("no progressive prompt: %s", loc)
			}
			page := b.do(t, "GET", loc, nil)
			p := readPasskeyPage(t, page)
			parsed, _ := url.Parse(loc)
			state := parsed.Query().Get("state")
			txn, _ := e.st.AuthTransactions().Get(context.Background(), u.TenantID, state)
			if txn.Params["za_pk_prompt"] == "" {
				t.Fatal("prompt decision not durable")
			}
			form := url.Values{"state": {state}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "skip": {"1"}}
			if snooze {
				form.Set("snooze", "1")
			}
			rec := b.do(t, "POST", "/u/passkey-enrollment", form)
			if !strings.HasPrefix(rec.Header().Get("Location"), "https://app.acme.test/cb?code=") {
				t.Fatalf("skip: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			if p.ChallengeID == "" {
				t.Fatal("missing challenge")
			}
			_, err := e.st.WebAuthn().GetSnooze(context.Background(), u.TenantID, u.UserID, "passkey-progressive", "acme.example.test", fixedNow())
			if (err == nil) != snooze {
				t.Fatalf("snooze=%v err=%v", snooze, err)
			}
			if snooze {
				if _, err = e.st.WebAuthn().GetSnooze(context.Background(), u.TenantID, u.UserID, "passkey-progressive", "acme.example.test", fixedNow().Add(31*24*time.Hour)); err == nil {
					t.Fatal("snooze exceeds 30 days")
				}
			}
			if page = b.do(t, "GET", loc, nil); !strings.Contains(page.Body.String(), "expired") {
				t.Fatalf("completed refresh: %d %s", page.Code, page.Body)
			}
		})
	}
}
func TestEnrollmentPromptBinding(t *testing.T) {
	e, b, _ := enrollmentEnv(t, false)
	_, state, _ := b.begin(t)
	loc := "/u/passkey-enrollment?state=" + state
	if page := b.do(t, "GET", loc, nil); !strings.Contains(page.Body.String(), "expired") {
		t.Fatalf("direct: %d %s", page.Code, page.Body)
	}
	loc = passwordEnrollment(t, b)
	other := e.browser("acme.example.test")
	if page := other.do(t, "GET", loc, nil); !strings.Contains(page.Body.String(), "expired") {
		t.Fatalf("other browser: %d %s", page.Code, page.Body)
	}
}

func TestEnrollmentPromptCannotCompleteThroughOtherPages(t *testing.T) {
	for _, path := range []string{"/u/consent", "/u/login/password"} {
		t.Run(path, func(t *testing.T) {
			_, b, _ := enrollmentEnv(t, false)
			loc := passwordEnrollment(t, b)
			page := b.do(t, "GET", loc, nil)
			parsed, _ := url.Parse(loc)
			rec := b.do(t, "POST", path, url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "action": {"accept"}, "password": {"alice password 1"}})
			if rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "expired") {
				t.Fatalf("pending enrollment completed through %s: %d %s %s", path, rec.Code, rec.Header().Get("Location"), rec.Body)
			}
		})
	}
}
func TestProgressiveEnrollmentSuccess(t *testing.T) {
	e, b, u := enrollmentEnv(t, false)
	capture := &pwlEvents{}
	e.h.Recorder = capture
	loc := passwordEnrollment(t, b)
	page := b.do(t, "GET", loc, nil)
	p := readPasskeyPage(t, page)
	raw := registrationFromPage(t, p, webauthntest.New(webauthntest.Options{}), "https://acme.example.test")
	parsed, _ := url.Parse(loc)
	rec := b.do(t, "POST", "/u/passkey-enrollment", url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "challenge_id": {p.ChallengeID}, "credential": {string(raw)}})
	if !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	aa, _ := e.st.MFA().ListAuthenticators(context.Background(), u.TenantID, u.UserID)
	if len(aa) != 1 {
		t.Fatalf("authenticators %d", len(aa))
	}
	events := capture.of("gd_enrollment_complete")
	if len(events) != 1 {
		t.Fatalf("success events=%+v", capture.events)
	}
	details, _ := json.Marshal(events[0].Details)
	if string(details) != `{"authenticator":{"type":"passkey"}}` {
		t.Fatalf("details=%s", details)
	}
}

func TestEnrollmentFailureLogsPasskeyMethod(t *testing.T) {
	e, b, _ := enrollmentEnv(t, false)
	capture := &pwlEvents{}
	e.h.Recorder = capture
	loc := passwordEnrollment(t, b)
	page := b.do(t, "GET", loc, nil)
	p := readPasskeyPage(t, page)
	parsed, _ := url.Parse(loc)
	rec := b.do(t, "POST", "/u/passkey-enrollment", url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "challenge_id": {p.ChallengeID}, "webauthn_error": {"NotAllowedError"}})
	if rec.Code != 400 || strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("failed ceremony continued: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	events := capture.of("gd_webauthn_enrollment_failed")
	if len(events) != 1 {
		t.Fatalf("failure events=%+v", capture.events)
	}
	details, _ := json.Marshal(events[0].Details["authentication_methods"])
	if string(details) != `["passkey"]` {
		t.Fatalf("failure method=%s", details)
	}
}
func registrationFromPage(t *testing.T, p passkeyPage, d *webauthntest.Authenticator, origin string) []byte {
	t.Helper()
	var o struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(p.Options, &o); err != nil {
		t.Fatal(err)
	}
	return d.Create(webauthn.CreationOptions{Challenge: decode64(t, o.Challenge), RPID: o.RP.ID, UserID: decode64(t, o.User.ID), Algs: webauthn.DefaultAlgs}, origin)
}

func decode64(t *testing.T, s string) []byte {
	t.Helper()
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func localEnrollment(t *testing.T, attachment string, platform bool) (*env, *browser, *store.User, string) {
	t.Helper()
	e, u, d, _ := passkeyEnv(t)
	e.h.Authz.Passkeys = e.h.Passkeys
	old := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/u/passkey-enrollment") {
			if r.Method == "POST" {
				tenantHandler(e.h.PasskeyEnrollmentPost, e.st).ServeHTTP(w, r)
			} else {
				tenantHandler(e.h.PasskeyEnrollmentPage, e.st).ServeHTTP(w, r)
			}
			return
		}
		old.ServeHTTP(w, r)
	})
	b := e.browser("acme.example.test")
	form, _ := passkeyForm(t, b, d)
	var credential map[string]any
	if err := json.Unmarshal([]byte(form.Get("credential")), &credential); err != nil {
		t.Fatal(err)
	}
	if attachment != "" {
		credential["authenticatorAttachment"] = attachment
	} else {
		delete(credential, "authenticatorAttachment")
	}
	raw, _ := json.Marshal(credential)
	form.Set("credential", string(raw))
	if platform {
		form.Set("platform_available", "1")
	}
	rec := b.do(t, "POST", "/u/login/passkey", form)
	return e, b, u, rec.Header().Get("Location")
}
func TestLocalEnrollmentOffered(t *testing.T) {
	e, b, u, loc := localEnrollment(t, "cross-platform", true)
	if !strings.HasPrefix(loc, "/u/passkey-enrollment-local?") {
		t.Fatalf("local prompt: %s", loc)
	}
	page := b.do(t, "GET", loc, nil)
	p := readPasskeyPage(t, page)
	var options struct {
		Selection struct {
			Attachment string `json:"authenticatorAttachment"`
		} `json:"authenticatorSelection"`
		Exclude []any `json:"excludeCredentials"`
	}
	if err := json.Unmarshal(p.Options, &options); err != nil {
		t.Fatal(err)
	}
	if options.Selection.Attachment != "platform" || len(options.Exclude) != 1 {
		t.Fatalf("local options: %s", p.Options)
	}
	parsed, _ := url.Parse(loc)
	state := parsed.Query().Get("state")
	rec := b.do(t, "POST", "/u/passkey-enrollment-local", url.Values{"state": {state}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "skip": {"1"}, "snooze": {"1"}})
	if !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("skip: %d %s", rec.Code, rec.Body)
	}
	cookie := b.cookies["za_pk_device"]
	if cookie == nil {
		t.Fatal("device cookie missing")
	}
	scope := secrets.HashToken(cookie.Value)
	if _, err := e.st.WebAuthn().GetSnooze(context.Background(), u.TenantID, u.UserID, "passkey-local", scope, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.WebAuthn().GetSnooze(context.Background(), u.TenantID, u.UserID, "passkey-local", secrets.HashToken("other-browser"), fixedNow()); err == nil {
		t.Fatal("snooze transferred browser")
	}
}
func TestLocalEnrollmentNotOfferedWithoutAttachment(t *testing.T) {
	for _, row := range []struct {
		attachment string
		platform   bool
	}{{"", true}, {"platform", true}, {"cross-platform", false}} {
		_, _, _, loc := localEnrollment(t, row.attachment, row.platform)
		if !strings.Contains(loc, "code=") {
			t.Fatalf("unexpected prompt attachment=%q platform=%v: %s", row.attachment, row.platform, loc)
		}
	}
}
func TestEnrollmentPromptRevocation(t *testing.T) {
	for _, change := range []string{"blocked", "disabled", "mfa"} {
		t.Run(change, func(t *testing.T) {
			e, b, u := enrollmentEnv(t, false)
			loc := passwordEnrollment(t, b)
			page := b.do(t, "GET", loc, nil)
			parsed, _ := url.Parse(loc)
			switch change {
			case "blocked":
				u.Blocked = true
				if err := e.st.Users().Update(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				c, _ := e.st.Connections().GetByName(context.Background(), u.TenantID, "Username-Password-Authentication")
				c.Extra["authentication_methods"] = map[string]any{}
				if err := e.st.Connections().Update(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			case "mfa":
				g, _ := e.st.MFA().GetGuardian(context.Background(), u.TenantID)
				g.Policies = []string{"all-applications"}
				g.Factors = map[string]bool{"otp": true}
				if err := e.st.MFA().PutGuardian(context.Background(), g, g.Version); err != nil {
					t.Fatal(err)
				}
			}
			rec := b.do(t, "POST", "/u/passkey-enrollment", url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "skip": {"1"}})
			if strings.Contains(rec.Header().Get("Location"), "code=") {
				t.Fatal("revoked policy issued code")
			}
		})
	}
}

func TestEnrollmentAfterMFAAndBeforeConsent(t *testing.T) {
	f := newMFAFixture(t)
	f.policy(t, "email")
	f.enrolled(t, "email", true)
	ctx := context.Background()
	cfg, _ := f.st.HostedLogins().Get(ctx, f.tn.ID)
	cfg.Prompts = map[string]any{"universal_login_experience": "new", "identifier_first": true}
	if err := f.st.HostedLogins().Put(ctx, cfg, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	c, _ := f.st.Connections().GetByName(ctx, f.tn.ID, "Username-Password-Authentication")
	c.Extra = map[string]any{"authentication_methods": map[string]any{"passkey": map[string]any{"enabled": true}}}
	if err := f.st.Connections().Update(ctx, c); err != nil {
		t.Fatal(err)
	}

	f.h.Passkeys = passkey.NewService(f.st, rpid.Policy{}, f.h.Now)
	f.h.Authz.Passkeys = f.h.Passkeys
	old := f.srv
	f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/u/passkey-enrollment") {
			if r.Method == "POST" {
				tenantHandler(f.h.PasskeyEnrollmentPost, f.st).ServeHTTP(w, r)
			} else {
				tenantHandler(f.h.PasskeyEnrollmentPage, f.st).ServeHTTP(w, r)
			}
			return
		}
		old.ServeHTTP(w, r)
	})
	rs, _ := f.st.ResourceServers().GetByIdentifier(ctx, f.tn.ID, "https://api.acme.test")
	rs.SkipConsentForVerifiableFirstPartyClients = false
	if err := f.st.ResourceServers().Update(ctx, rs); err != nil {
		t.Fatal(err)
	}
	loc := passwordEnrollment(t, f.b, "audience", "https://api.acme.test", "scope", "openid read:things")
	parsed, _ := url.Parse(loc)
	if parsed.Path != "/u/mfa" {
		t.Fatalf("MFA must precede prompt and consent: %s", loc)
	}
	f.state = parsed.Query().Get("state")
	if page := f.b.do(t, "GET", "/u/passkey-enrollment?state="+f.state, nil); !strings.Contains(page.Body.String(), "expired") {
		t.Fatal("pending MFA granted enrollment")
	}
	f.page(t, "/u/mfa")
	rec := f.post(t, "/u/mfa-email-challenge", url.Values{"code": {f.mail.codes[len(f.mail.codes)-1]}})
	loc = rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/u/passkey-enrollment?") {
		t.Fatalf("after MFA: %d %s %s", rec.Code, loc, rec.Body)
	}
	page := f.b.do(t, "GET", loc, nil)
	parsed, _ = url.Parse(loc)
	rec = f.b.do(t, "POST", "/u/passkey-enrollment", url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "skip": {"1"}})
	loc = rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/u/consent?") {
		t.Fatalf("prompt must precede consent: %d %s %s", rec.Code, loc, rec.Body)
	}
	page = f.b.do(t, "GET", loc, nil)
	parsed, _ = url.Parse(loc)
	rec = f.b.do(t, "POST", "/u/consent", url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "action": {"accept"}})
	if !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("after consent: %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

func TestProgressiveEnrollmentEligibility(t *testing.T) {
	for _, kind := range []string{"existing-rp", "disabled", "max20", "snoozed"} {
		t.Run(kind, func(t *testing.T) {
			e, b, u := enrollmentEnv(t, kind == "existing-rp")
			ctx := context.Background()
			switch kind {
			case "disabled":
				c, _ := e.st.Connections().GetByName(ctx, u.TenantID, "Username-Password-Authentication")
				c.Extra["passkey_options"] = map[string]any{"progressive_enrollment_enabled": false}
				if err := e.st.Connections().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
			case "max20":
				for i := 0; i < 20; i++ {
					a := &store.Authenticator{TenantID: u.TenantID, UserID: u.UserID, ID: fmt.Sprintf("key-%d", i), Type: "passkey", Confirmed: true, RPID: "other.example.test", CredentialID: []byte{byte(i + 1)}, PublicKey: []byte{1}, CreatedAt: fixedNow()}
					if err := e.st.WebAuthn().CreatePasskey(ctx, a, 20); err != nil {
						t.Fatal(err)
					}
				}
			case "snoozed":
				if err := e.st.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{TenantID: u.TenantID, UserID: u.UserID, Kind: "passkey-progressive", ScopeKey: "acme.example.test", Until: fixedNow().Add(30 * 24 * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			if loc := passwordEnrollment(t, b); !strings.Contains(loc, "code=") {
				t.Fatalf("ineligible %s: %s", kind, loc)
			}
		})
	}
}
func TestProgressiveEnrollmentOfferedAgainDay31(t *testing.T) {
	e, b, u := enrollmentEnv(t, false)
	now := fixedNow()
	e.h.Now = func() time.Time { return now }
	e.h.Authz.Now = e.h.Now
	e.h.Sessions.Now = e.h.Now
	e.h.Passkeys.Now = e.h.Now
	if err := e.st.WebAuthn().PutSnooze(context.Background(), &store.WebAuthnSnooze{TenantID: u.TenantID, UserID: u.UserID, Kind: "passkey-progressive", ScopeKey: "acme.example.test", Until: now.Add(30 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if loc := passwordEnrollment(t, b); !strings.Contains(loc, "code=") {
		t.Fatalf("during snooze: %s", loc)
	}
	now = now.Add(31 * 24 * time.Hour)
	b = e.browser(b.host)
	if loc := passwordEnrollment(t, b); !strings.HasPrefix(loc, "/u/passkey-enrollment?") {
		t.Fatalf("day31: %s", loc)
	}
}

func TestEnrollmentPromptConcurrentAnswer(t *testing.T) {
	e, b, _ := enrollmentEnv(t, false)
	loc := passwordEnrollment(t, b)
	page := b.do(t, "GET", loc, nil)
	parsed, _ := url.Parse(loc)
	form := url.Values{"state": {parsed.Query().Get("state")}, "csrf": {csrfField.FindStringSubmatch(page.Body.String())[1]}, "skip": {"1"}, "hosted_revision": {revisionFrom(t, page.Body.String())}}
	results := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			r := httptest.NewRequest("POST", "https://"+b.host+"/u/passkey-enrollment", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range b.cookies {
				r.AddCookie(c)
			}
			w := httptest.NewRecorder()
			e.srv.ServeHTTP(w, r)
			results <- w
		}()
	}
	wins := 0
	for range 2 {
		select {
		case rec := <-results:
			if strings.Contains(rec.Header().Get("Location"), "code=") {
				wins++
			}
		case <-time.After(15 * time.Second):
			t.Fatal("answer did not complete")
		}
	}
	if wins != 1 {
		t.Fatalf("redirect winners=%d", wins)
	}
}
func TestEnrollmentPromptPurposeBinding(t *testing.T) {
	e, b, u := enrollmentEnv(t, false)
	loc := passwordEnrollment(t, b)
	page := b.do(t, "GET", loc, nil)
	p := readPasskeyPage(t, page)
	parsed, _ := url.Parse(loc)
	txn, err := e.st.AuthTransactions().Get(context.Background(), u.TenantID, parsed.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	before := txn.Params["za_pk_prompt"]
	page = b.do(t, "GET", loc, nil)
	latest, _ := e.st.AuthTransactions().Get(context.Background(), u.TenantID, txn.ID)
	if before != latest.Params["za_pk_prompt"] {
		t.Fatal("GET recomputed prompt authority")
	}
	conn, _ := e.st.Connections().GetByName(context.Background(), u.TenantID, "Username-Password-Authentication")
	_, err = e.h.Passkeys.Take(context.Background(), u.TenantID, p.ChallengeID, passkey.Binding{Purpose: passkey.PasskeyRegister, RPID: "acme.example.test", Origins: []string{"https://acme.example.test"}, TxnID: txn.ID, CookieHash: txn.CookieHash, ClientID: txn.ClientID, Realm: conn.Name, UserID: u.UserID})
	if err == nil {
		t.Fatal("progressive challenge accepted for signup purpose")
	}
}

func TestProgressiveEnrollmentAfterPasswordSignup(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	tn := mustTenant(t, e, "acme")
	conn, _ := e.st.Connections().GetByName(context.Background(), tn.ID, "Username-Password-Authentication")
	conn.Extra["passkey_options"] = map[string]any{"progressive_enrollment_enabled": true}
	if err := e.st.Connections().Update(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "progressive-signup@acme.test")
	next := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}})
	page = b.do(t, "GET", next.Header().Get("Location"), nil)
	done := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "password": {"correct horse battery"}})
	if !strings.HasPrefix(done.Header().Get("Location"), "/u/passkey-enrollment?") {
		t.Fatalf("password signup continuation: %d %s %s", done.Code, done.Header().Get("Location"), done.Body)
	}
	assertSessionMethods(t, b, "pwd")
}

func TestProgressiveEnrollmentInvitationWaitsForVerification(t *testing.T) {
	e, _, _ := enrollmentEnv(t, false)
	org, conn, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, true)
	ctx := context.Background()
	const email = "progressive-invite@acme.test"
	in := &store.OrganizationInvitation{TenantID: org.TenantID, OrganizationID: org.ID, ID: "progressive-invite", ClientID: "spa", InviteeEmail: email, ConnectionID: conn.ID, TicketHash: orglogin.InvitationTicketHash("progressive-ticket"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
	if err := e.st.OrganizationsII().CreateInvitation(ctx, in); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "organization", org.ID, "invitation", "progressive-ticket", "screen_hint", "signup")
	done := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {email}, "password": {"correct horse battery"}})
	if strings.Contains(done.Header().Get("Location"), "/u/passkey-enrollment") || strings.Contains(done.Header().Get("Location"), "code=") {
		t.Fatalf("unverified invitation continued: %s", done.Header().Get("Location"))
	}
	u, err := e.st.Users().FindByLogin(ctx, org.TenantID, conn.Name, email)
	if err != nil {
		t.Fatal(err)
	}
	u.EmailVerified = true
	if err = e.st.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	// The verification subsystem commits ownership; the original password
	// continuation then authenticates against the same bound invitation.
	page := b.do(t, "GET", "/u/login?state="+state, nil)
	csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	done = b.do(t, "POST", "/u/login", url.Values{"state": {state}, "csrf": {csrf}, "username": {email}})
	page = b.do(t, "GET", done.Header().Get("Location"), nil)
	csrf = csrfField.FindStringSubmatch(page.Body.String())[1]
	done = b.do(t, "POST", "/u/login/password", url.Values{"state": {state}, "csrf": {csrf}, "password": {"correct horse battery"}})
	if !strings.HasPrefix(done.Header().Get("Location"), "/u/passkey-enrollment?") {
		t.Fatalf("verified invitation continuation: %d %s %s", done.Code, done.Header().Get("Location"), done.Body)
	}
	member, err := e.st.Organizations().IsMember(ctx, org.TenantID, org.ID, u.UserID)
	if err != nil || !member {
		t.Fatalf("invitation membership: %v %v", member, err)
	}
}
