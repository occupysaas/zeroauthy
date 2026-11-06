package login

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

func signupPasskeyEnv(t *testing.T) (*env, *pwlEvents) {
	t.Helper()
	e, _, _, _ := passkeyEnv(t)
	// These Task 10 tests isolate signup. Task 11 exercises the subsequent prompt.
	ctx := context.Background()
	tn := mustTenant(t, e, "acme")
	conn, _ := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
	conn.Extra["passkey_options"] = map[string]any{"progressive_enrollment_enabled": false}
	if err := e.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	capture := &pwlEvents{}
	e.h.Recorder = capture
	original := e.srv
	e.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(logs.WithRecorder(r.Context(), capture))
		if strings.HasPrefix(r.URL.Path, "/u/signup/") {
			var fn http.HandlerFunc = e.h.SignupPage
			if r.Method == "POST" {
				fn = e.h.SignupSubmit
			}
			tenantHandler(fn, e.st).ServeHTTP(w, r)
			return
		}
		original.ServeHTTP(w, r)
	})
	return e, capture
}
func signupID(t *testing.T, b *browser, email string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	_, state, csrf := b.begin(t)
	redirect := b.do(t, "GET", "/u/signup?state="+state, nil)
	if redirect.Code != 303 || !strings.HasPrefix(redirect.Header().Get("Location"), "/u/signup/identifier?") {
		t.Fatalf("signup entry = %d %s", redirect.Code, redirect.Body)
	}
	page := b.do(t, "GET", redirect.Header().Get("Location"), nil)
	if page.Code != 200 || strings.Contains(page.Body.String(), `name="password"`) {
		t.Fatalf("identifier page %d %s", page.Code, page.Body)
	}
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "email": {email}, "name": {"New Person"}}
	next := b.do(t, "POST", "/u/signup/identifier", form)
	if next.Code != 303 {
		return next, state, csrf
	}
	return b.do(t, "GET", next.Header().Get("Location"), nil), state, csrf
}
func signupCredential(t *testing.T, p passkeyPage) []byte {
	t.Helper()
	var o struct {
		Challenge              string
		RP                     struct{ ID string }
		User                   struct{ ID, Name, DisplayName string }
		AuthenticatorSelection struct{ ResidentKey, UserVerification string }
	}
	if err := json.Unmarshal(p.Options, &o); err != nil {
		t.Fatal(err)
	}
	ch, _ := base64.RawURLEncoding.DecodeString(o.Challenge)
	handle, _ := base64.RawURLEncoding.DecodeString(o.User.ID)
	return webauthntest.New(webauthntest.Options{}).Create(webauthn.CreationOptions{Challenge: ch, RPID: o.RP.ID, UserID: handle, UserName: o.User.Name, DisplayName: o.User.DisplayName, ResidentKey: o.AuthenticatorSelection.ResidentKey, UserVerification: o.AuthenticatorSelection.UserVerification}, "https://acme.example.test")
}
func TestPasskeySignup(t *testing.T) {
	e, capture := signupPasskeyEnv(t)
	wrapped := events.Wrap(e.st, events.Config{})
	e.h.Store = wrapped
	e.h.Database.Store = wrapped
	e.h.Passkeys.Store = wrapped
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "new@acme.test")
	p := readPasskeyPage(t, page)
	for _, label := range []string{"Create a passkey", "Create a password", "Back"} {
		if !strings.Contains(page.Body.String(), label) {
			t.Fatalf("missing %s", label)
		}
	}
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}, "email": {"tampered@acme.test"}, "name": {"Tampered"}}
	result := b.do(t, "POST", "/u/signup/passkey", form)
	if result.Code != 302 {
		t.Fatalf("registration %d %s", result.Code, result.Body)
	}
	tn := mustTenant(t, e, "acme")
	u, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "new@acme.test")
	if err != nil || u.Name != "New Person" || u.Identities[0].PasswordHash != "" {
		t.Fatalf("user %+v %v", u, err)
	}
	methods, err := e.st.MFA().ListAuthenticators(context.Background(), tn.ID, u.UserID)
	if err != nil || len(methods) != 1 || methods[0].Type != "passkey" {
		t.Fatalf("methods %+v %v", methods, err)
	}
	created, err := e.st.Events().EventsAfter(context.Background(), tn.ID, 0, []string{"user.created"}, 100, time.Now().Add(time.Hour))
	if err != nil || len(created) != 1 {
		t.Fatalf("user.created %+v %v", created, err)
	}
	if len(e.mail.sent) != 1 {
		t.Fatalf("verification messages %+v", e.mail.sent)
	}

	assertSessionMethods(t, b, "passkey")
	conn, _ := e.st.Connections().GetByName(context.Background(), tn.ID, "Username-Password-Authentication")
	if _, err := e.h.Database.Login(context.Background(), conn, "new@acme.test", "any password"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("passkey-only password login %v", err)
	}
	rawEvents, _ := json.Marshal(capture.events)
	for _, secret := range []string{p.ChallengeID, form.Get("credential")} {
		if strings.Contains(string(rawEvents), secret) || strings.Contains(e.logs.String(), secret) {
			t.Fatal("ceremony secret in log")
		}
	}

	success := capture.of("ss")
	if len(success) != 1 {
		t.Fatalf("signup logs %+v", capture.events)
	}
	data, _ := json.Marshal(success[0].Details)
	if string(data) != `{"authentication_methods":["passkey"]}` {
		t.Fatalf("signup details %s", data)
	}
}
func TestPasskeySignupWithoutScript(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	setProtectionLimits(t, e.st, 3, 30, 1)
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "password@acme.test")
	if !strings.Contains(page.Body.String(), `action="/u/signup/password"`) {
		t.Fatal("missing plain password form")
	}
	next := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}})
	if next.Code != 303 {
		t.Fatalf("fallback %d %s", next.Code, next.Body)
	}
	page = b.do(t, "GET", next.Header().Get("Location"), nil)
	if !strings.Contains(page.Body.String(), `name="password"`) || strings.Contains(page.Body.String(), "za-webauthn") {
		t.Fatal("missing password-only page")
	}
	done := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "password": {"correct horse battery"}, "email": {"tampered@acme.test"}})
	if done.Code != 302 {
		t.Fatalf("password signup %d %s", done.Code, done.Body)
	}
	assertSessionMethods(t, b, "pwd")
}
func TestPasswordSignupLogsPwd(t *testing.T) {
	e := newEnv(t)
	capture := &pwlEvents{}
	e.h.Recorder = capture
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t, "screen_hint", "signup")
	result := b.do(t, "POST", "/u/signup", url.Values{"state": {state}, "csrf": {csrf}, "email": {"new@acme.test"}, "password": {"correct horse battery"}})
	success := capture.of("ss")
	if result.Code != 302 || len(success) != 1 {
		t.Fatalf("signup %d %+v", result.Code, capture.events)
	}
	data, _ := json.Marshal(success[0].Details)
	if string(data) != `{"authentication_methods":["pwd"]}` {
		t.Fatalf("details %s", data)
	}
}
func TestPasskeySignupRules(t *testing.T) {
	for _, kind := range []string{"exists", "failure", "stale", "direct", "disabled", "password-bypass"} {
		t.Run(kind, func(t *testing.T) {
			e, capture := signupPasskeyEnv(t)
			b := e.browser("acme.example.test")
			email := "rules@acme.test"
			if kind == "exists" {
				email = "alice@acme.test"
			}
			page, state, csrf := signupID(t, b, email)
			if kind == "exists" {
				if page.Code != 400 || !strings.Contains(page.Body.String(), "already exists") {
					t.Fatalf("existing %d %s", page.Code, page.Body)
				}
				return
			}
			p := readPasskeyPage(t, page)
			form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}}
			path := "/u/signup/passkey"
			switch kind {
			case "failure":
				form.Set("credential", `{}`)
			case "stale":
				form.Set("hosted_revision", "-1")
			case "direct":
				form.Set("password", "correct horse battery")
				form.Set("email", "bypass@acme.test")
				path = "/u/signup"
			case "password-bypass":
				form.Set("password", "correct horse battery")
				path = "/u/signup/password"
			case "disabled":
				tn := mustTenant(t, e, "acme")
				c, _ := e.st.Connections().GetByName(context.Background(), tn.ID, "Username-Password-Authentication")
				c.DisableSignup = true
				if err := e.st.Connections().Update(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			}
			result := b.do(t, "POST", path, form)
			if result.Code == 302 {
				t.Fatalf("policy bypass %s", result.Body)
			}
			tn := mustTenant(t, e, "acme")
			if _, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", email); err != store.ErrNotFound {
				t.Fatalf("unexpected user %v", err)
			}
			if kind == "failure" {
				if len(capture.of("gd_webauthn_enrollment_failed")) != 1 || !strings.Contains(result.Body.String(), "could not create") {
					t.Fatalf("failure %d %s %+v", result.Code, result.Body, capture.events)
				}
			}
		})
	}
}

func TestPasskeySignupBudgetBeforeExistence(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	setProtectionLimits(t, e.st, 3, 30, 1)
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "alice@acme.test")
	if page.Code != 400 {
		t.Fatal(page.Code)
	}
	blocked := b.do(t, "POST", "/u/signup/identifier", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "email": {"alice@acme.test"}})
	if blocked.Code != 429 || strings.Contains(blocked.Body.String(), "already exists") {
		t.Fatalf("enumeration before budget %d %s", blocked.Code, blocked.Body)
	}
}
func TestPasskeySignupActions(t *testing.T) {
	for _, deny := range []bool{false, true} {
		t.Run(fmt.Sprint(deny), func(t *testing.T) {
			e, _ := signupPasskeyEnv(t)
			tn := mustTenant(t, e, "acme")
			wrapper, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
			a := actionstest.NewOffline(t, e.st, wrapper)
			script := `exports.onExecutePreUserRegistration=(event,api)=>{ if (JSON.stringify(event.request.body).includes('credential') || JSON.stringify(event).includes('attestationObject')) throw Error('leak'); api.user.setUserMetadata('pre_ran',true); };`
			if deny {
				script = `exports.onExecutePreUserRegistration=(event,api)=>api.access.deny('denied','Signup is refused');`
			}
			a.Bind(t, tn.ID, actions.TriggerPreUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPreUserRegistration, "signup-pre", script))
			a.Bind(t, tn.ID, actions.TriggerPostUserRegistration, a.Deploy(t, tn.ID, actions.TriggerPostUserRegistration, "signup-post", `exports.onExecutePostUserRegistration=()=>{};`))
			e.h.Actions = a.Engine
			b := e.browser("acme.example.test")
			page, state, csrf := signupID(t, b, "action@acme.test")
			p := readPasskeyPage(t, page)
			form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}}
			done := b.do(t, "POST", "/u/signup/passkey", form)
			u, err := e.st.Users().FindByLogin(context.Background(), tn.ID, "Username-Password-Authentication", "action@acme.test")
			if deny {
				if done.Code != 400 || err != store.ErrNotFound || len(e.mail.sent) != 0 {
					t.Fatalf("denied signup %d %+v %v", done.Code, u, err)
				}
				return
			}
			if done.Code != 302 || err != nil || u.UserMetadata["pre_ran"] != true {
				t.Fatalf("Action did not run before creation %d %+v %v %s", done.Code, u, err, done.Body)
			}
			jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now(), time.Minute, 10)
			if err != nil || len(jobs) != 1 {
				t.Fatalf("post jobs %+v %v", jobs, err)
			}
		})
	}
}

func TestPasskeySignupAvailability(t *testing.T) {
	for _, kind := range []string{"disabled", "invitation", "organization"} {
		t.Run(kind, func(t *testing.T) {
			e, _ := signupPasskeyEnv(t)
			b := e.browser("acme.example.test")
			ctx := context.Background()
			var extra []string
			if kind == "disabled" {
				tn := mustTenant(t, e, "acme")
				c, _ := e.st.Connections().GetByName(ctx, tn.ID, "Username-Password-Authentication")
				c.Extra = nil
				if err := e.st.Connections().Update(ctx, c); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "disabled" {
				org, c, _ := organizationFixture(t, e, store.OrgBehaviorNoPrompt, true, kind == "invitation")
				extra = []string{"organization", org.ID}
				if kind == "invitation" {
					in := &store.OrganizationInvitation{TenantID: org.TenantID, OrganizationID: org.ID, ID: "signup-invite", ClientID: "spa", InviteeEmail: "invite@acme.test", ConnectionID: c.ID, TicketHash: orglogin.InvitationTicketHash("signup-ticket"), WrappedTicket: []byte("sealed"), ExpiresAt: time.Now().Add(time.Hour)}
					if err := e.st.OrganizationsII().CreateInvitation(ctx, in); err != nil {
						t.Fatal(err)
					}
					extra = append(extra, "invitation", "signup-ticket")
				}
			}
			_, state, _ := b.begin(t, extra...)
			page := b.do(t, "GET", "/u/signup?state="+state, nil)
			if kind == "organization" {
				if page.Code != 403 {
					t.Fatalf("org signup %d %s", page.Code, page.Body)
				}
				return
			}
			if page.Code != 200 || strings.Contains(page.Body.String(), "za-webauthn") || !strings.Contains(page.Body.String(), `name="password"`) {
				t.Fatalf("legacy/invitation page %d %s", page.Code, page.Body)
			}
		})
	}
}
func TestPasskeySignupBindings(t *testing.T) {
	for _, kind := range []string{"csrf", "cookie", "host", "challenge", "profile-rule", "connection", "replay"} {
		t.Run(kind, func(t *testing.T) {
			e, _ := signupPasskeyEnv(t)
			b := e.browser("acme.example.test")
			page, state, csrf := signupID(t, b, "binding@acme.test")
			p := readPasskeyPage(t, page)
			form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}}
			switch kind {
			case "csrf":
				form.Set("csrf", "wrong")
			case "cookie":
				b.cookies["za_txn_"+state] = &http.Cookie{Name: "za_txn_" + state, Value: "wrong"}
			case "host":
				b.host = "globex.example.test"
			case "challenge":
				form.Set("challenge_id", "wrong")
			case "profile-rule", "connection":
				tn := mustTenant(t, e, "acme")
				c, _ := e.st.Connections().GetByName(context.Background(), tn.ID, "Username-Password-Authentication")
				if kind == "connection" {
					c.Extra = nil
				} else {
					c.Extra["attributes"] = map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}, "signup": map[string]any{"status": "required"}}}
				}
				if err := e.st.Connections().Update(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			case "replay":
				if done := b.do(t, "POST", "/u/signup/passkey", form); done.Code != 302 {
					t.Fatalf("first signup %d %s", done.Code, done.Body)
				}
			}
			done := b.do(t, "POST", "/u/signup/passkey", form)
			if done.Code == 302 {
				t.Fatalf("binding bypass %s", kind)
			}
		})
	}
}

func TestPasskeySignupBotPolicyRecheck(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	setProtectionLimits(t, e.st, 3, 30, 1)
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "bot@acme.test")
	p := readPasskeyPage(t, page)
	tn := mustTenant(t, e, "acme")
	tn.ProtectionSettings.Bot.ChallengePasswordPolicy = "always"
	tn.ProtectionSettings.CAPTCHA.ActiveProviderID = "hcaptcha"
	tn.ProtectionSettings.CAPTCHA.HCaptcha.SiteKey = "site"
	if err := e.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	stub := &captchaStub{}
	e.h.Protection = &protection.Service{Store: e.st, Now: fixedNow, CaptchaVerifier: stub}
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}}
	done := b.do(t, "POST", "/u/signup/passkey", form)
	if done.Code != 400 || stub.calls != 0 || !strings.Contains(done.Body.String(), "js.hcaptcha.com") {
		t.Fatalf("captcha bypass %d %s", done.Code, done.Body)
	}
	retry := readPasskeyPage(t, done)
	form.Set("hosted_revision", revisionFrom(t, done.Body.String()))
	form.Set("challenge_id", retry.ChallengeID)
	form.Set("credential", string(signupCredential(t, retry)))
	form.Set("h-captcha-response", "good")
	if accepted := b.do(t, "POST", "/u/signup/passkey", form); accepted.Code != 302 {
		t.Fatalf("CAPTCHA rejection spent credit %d %s", accepted.Code, accepted.Body)
	}

}

func TestPasskeySignupPhoneAttribute(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	tn := mustTenant(t, e, "acme")
	conn, _ := e.st.Connections().GetByName(context.Background(), tn.ID, "Username-Password-Authentication")
	conn.Extra["attributes"] = map[string]any{"phone_number": map[string]any{"identifier": map[string]any{"active": true}, "signup": map[string]any{"status": "required", "verification": map[string]any{"active": false}}}}
	if err := e.st.Connections().Update(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	b := e.browser("acme.example.test")
	_, state, csrf := b.begin(t)
	entry := b.do(t, "GET", "/u/signup?state="+state, nil)
	page := b.do(t, "GET", entry.Header().Get("Location"), nil)
	if !strings.Contains(page.Body.String(), `name="phone_number"`) {
		t.Fatal("missing phone attribute")
	}
	next := b.do(t, "POST", "/u/signup/identifier", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "phone_number": {"+14155550199"}})
	if next.Code != 303 {
		t.Fatalf("phone identifier %d %s", next.Code, next.Body)
	}
	page = b.do(t, "GET", next.Header().Get("Location"), nil)
	p := readPasskeyPage(t, page)
	if !strings.Contains(string(p.Options), "+14155550199") {
		t.Fatalf("creation user name %s", p.Options)
	}
	done := b.do(t, "POST", "/u/signup/passkey", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}})
	users, err := e.st.Phone().FindUsersByPhone(context.Background(), tn.ID, conn.Name, "+14155550199")
	if done.Code != 302 || err != nil || len(users) != 1 || users[0].Identities[0].PasswordHash != "" {
		t.Fatalf("phone signup %d %+v %v %s", done.Code, users, err, done.Body)
	}
}

func TestPasskeySignupInvalidRPID(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	e.h.Passkeys.RPID.Log = e.h.Log
	tn := mustTenant(t, e, "acme")
	ctx := context.Background()
	host := "bad.acme.test"
	if err := e.st.CustomDomains().Create(ctx, &store.CustomDomain{TenantID: tn.ID, ID: "bad-signup", Domain: host, RelyingPartyIdentifier: "unrelated.test", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: host, TenantID: tn.ID, DomainID: "bad-signup", Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	b := e.browser(host)
	_, state, _ := b.begin(t)
	page := b.do(t, "GET", "/u/signup?state="+state, nil)
	if !strings.Contains(e.logs.String(), "unusable WebAuthn relying party ID") {
		t.Fatal("missing RP diagnostic")
	}
	if page.Code != 400 || strings.Contains(page.Body.String(), "za-webauthn") {
		t.Fatalf("invalid RP signup %d %s", page.Code, page.Body)
	}
}

type signupConflictStore struct{ store.Store }

func (s signupConflictStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(signupConflictStore{tx}) })
}
func (s signupConflictStore) WebAuthn() store.WebAuthn {
	return signupConflictWebAuthn{s.Store.WebAuthn()}
}

type signupConflictWebAuthn struct{ store.WebAuthn }

func (signupConflictWebAuthn) CreateUserWithPasskey(context.Context, *store.User, *store.Authenticator) error {
	return store.ErrConflict
}
func TestPasskeySignupCredentialConflictPrivacy(t *testing.T) {
	e, capture := signupPasskeyEnv(t)
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "conflict@acme.test")
	p := readPasskeyPage(t, page)
	e.h.Database.Store = signupConflictStore{e.st}
	done := b.do(t, "POST", "/u/signup/passkey", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "challenge_id": {p.ChallengeID}, "credential": {string(signupCredential(t, p))}})
	if done.Code != 400 || strings.Contains(done.Body.String(), "already exists") || !strings.Contains(done.Body.String(), "could not create") || len(capture.of("gd_webauthn_enrollment_failed")) != 1 {
		t.Fatalf("credential existence leaked %d %s %+v", done.Code, done.Body, capture.events)
	}
}

func TestPasskeySignupPasswordCreditSingleUse(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	setProtectionLimits(t, e.st, 3, 30, 1)
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "credit@acme.test")
	next := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}})
	if next.Code != 303 {
		t.Fatal(next.Code)
	}
	page = b.do(t, "GET", next.Header().Get("Location"), nil)
	form := url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "password": {"x"}}
	failed := b.do(t, "POST", "/u/signup/password", form)
	if failed.Code != 400 || !strings.Contains(failed.Body.String(), "at least 8") {
		t.Fatalf("first attempt double charged %d %s", failed.Code, failed.Body)
	}
	form.Set("hosted_revision", revisionFrom(t, failed.Body.String()))
	form.Set("password", "correct horse battery")
	blocked := b.do(t, "POST", "/u/signup/password", form)
	if blocked.Code != 429 {
		t.Fatalf("admission credit reused %d %s", blocked.Code, blocked.Body)
	}
}

func TestPasskeySignupCreditConcurrent(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	setProtectionLimits(t, e.st, 3, 30, 1)
	b := e.browser("acme.example.test")
	_, state, _ := signupID(t, b, "race-credit@acme.test")
	var f *flow
	var req *http.Request
	r := httptest.NewRequest("GET", "https://"+b.host+"/u/signup/passkey?state="+state, nil)
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	tenantHandler(func(w http.ResponseWriter, r *http.Request) {
		var err error
		f, err = e.h.load(r, state)
		if err != nil {
			t.Fatal(err)
		}
		req = r
	}, e.st).ServeHTTP(httptest.NewRecorder(), r)
	first, err := e.h.peekSignupAdmission(req, f)
	if err != nil || first == nil {
		t.Fatalf("missing credit %v", err)
	}
	second, err := e.h.peekSignupAdmission(req, f)
	if err != nil || second == nil {
		t.Fatalf("missing competing credit %v", err)
	}
	var wg sync.WaitGroup
	out := make(chan bool, 2)
	errs := make(chan error, 2)
	for _, row := range []*store.MFAChallenge{first, second} {
		wg.Go(func() {
			admitted, err := e.h.consumeSignupAdmission(req, f, row)
			if err != nil {
				errs <- err
				return
			}
			dec, err := e.h.protectionService().Begin(req.Context(), protection.Attempt{Tenant: f.res.Tenant, Connection: f.conn, IP: "192.0.2.1", Flow: "signup", RegistrationAdmitted: admitted})
			if err != nil {
				errs <- err
				return
			}
			if dec.Allowed {
				err = e.h.protectionService().Finish(req.Context(), dec.Receipt, "failure")
			}
			if err != nil {
				errs <- err
				return
			}
			out <- dec.Allowed
		})
	}
	wg.Wait()
	close(out)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	allowed := 0
	for ok := range out {
		if ok {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("credit allowed %d attempts", allowed)
	}
}
func TestPasskeySignupCreditIPChange(t *testing.T) {
	e, _ := signupPasskeyEnv(t)
	setProtectionLimits(t, e.st, 3, 30, 1)
	b := e.browser("acme.example.test")
	page, state, csrf := signupID(t, b, "ip-credit@acme.test")
	next := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}})
	page = b.do(t, "GET", next.Header().Get("Location"), nil)
	tn := mustTenant(t, e, "acme")
	conn, _ := e.st.Connections().GetByName(context.Background(), tn.ID, "Username-Password-Authentication")
	dec, err := e.h.protectionService().Begin(context.Background(), protection.Attempt{Tenant: tn, Connection: conn, IP: "198.51.100.8", Flow: "signup"})
	if err != nil || !dec.Allowed {
		t.Fatalf("new IP budget %v", err)
	}
	if err := e.h.protectionService().Finish(context.Background(), dec.Receipt, "failure"); err != nil {
		t.Fatal(err)
	}
	b.remoteAddr = "198.51.100.8:1234"
	done := b.do(t, "POST", "/u/signup/password", url.Values{"state": {state}, "csrf": {csrf}, "hosted_revision": {revisionFrom(t, page.Body.String())}, "password": {"correct horse battery"}})
	if done.Code != 429 {
		t.Fatalf("transferred IP admission %d %s", done.Code, done.Body)
	}
	txn, _ := e.st.AuthTransactions().Get(context.Background(), tn.ID, state)
	if _, err := e.st.MFA().GetChallenge(context.Background(), tn.ID, signupAdmissionID(txn.HostedState.Identifier), fixedNow()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old credit retained %v", err)
	}
}
