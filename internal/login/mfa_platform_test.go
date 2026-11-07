package login

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPlatformProgressiveEnrollment(t *testing.T) {
	for _, choice := range []string{"remind", "refuse", "skip"} {
		t.Run(choice, func(t *testing.T) {
			f := newRoamingMFAFixture(t)
			f.policy(t, "otp", "webauthn-platform")
			secret := f.enrolled(t, "otp", false)
			old := f.srv
			f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/130.0 Safari/537.36")
				old.ServeHTTP(w, r)
			})
			_, s, c := f.b.begin(t)
			rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
			loc, _ := url.Parse(rec.Header().Get("Location"))
			f.state = loc.Query().Get("state")
			f.page(t, "/u/mfa-detect-browser-capabilities")
			rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}, "platform": {"1"}})
			if rec.Code != 303 {
				t.Fatalf("detection %d %s", rec.Code, rec.Body)
			}
			f.page(t, "/u/mfa")
			rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
			if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "mfa-webauthn-platform-enrollment") {
				t.Fatalf("progression %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			page := f.page(t, "/u/mfa-webauthn-platform-enrollment")
			if strings.Contains(page.Body.String(), "action=another") {
				t.Fatal("platform enrollment exposed broken alternate-method loop")
			}

			for _, text := range []string{"Continue", "Remind me later", "Not on this device", "Not now"} {
				if !strings.Contains(page.Body.String(), text) {
					t.Fatalf("missing %q", text)
				}
			}
			rec = f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"platform_choice": {choice}})
			if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
				t.Fatalf("skip completion %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			kind := "platform-" + choice
			row, err := f.st.WebAuthn().GetSnooze(context.Background(), f.tn.ID, f.uid, kind, "macos/chrome/desktop", *f.clock)
			if choice == "skip" {
				if err == nil {
					t.Fatal("not-now persisted")
				}
				return
			}
			days := 14
			if choice == "refuse" {
				days = 365
				if f.b.cookies["za_platform_refuse"] == nil {
					t.Fatal("missing refusal cookie")
				}
			}
			if err != nil || !row.Until.Equal(f.clock.Add(time.Duration(days)*24*time.Hour)) {
				t.Fatalf("snooze %+v %v", row, err)
			}
			if _, err = f.st.WebAuthn().GetSnooze(context.Background(), f.tn.ID, f.uid, kind, "macos/chrome/desktop", row.Until); err == nil {
				t.Fatal("expired snooze live")
			}
		})
	}
}

func TestPlatformRulesTicketOtherProofFirst(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "enroll-other", true: "challenge-other"}[existing], func(t *testing.T) {
			f := newRoamingMFAFixture(t)
			f.policy(t, "otp", "webauthn-platform")
			secret := ""
			if existing {
				secret = f.enrolled(t, "otp", false)
			}
			raw := "platform-ticket"
			if err := f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, UserID: f.uid, Hash: secrets.HashToken(raw), Factor: "webauthn-platform", ExpiresAt: f.clock.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			rec := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != 303 {
				t.Fatalf("ticket %d %s", rec.Code, rec.Body)
			}
			f.state = loc.Query().Get("state")
			f.page(t, "/u/mfa-detect-browser-capabilities")
			rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}, "platform": {"1"}})
			if rec.Code != 303 {
				t.Fatalf("detection %d %s", rec.Code, rec.Body)
			}
			page := f.page(t, "/u/mfa")
			path := "/u/mfa-otp-challenge"
			if !existing {
				path = "/u/mfa-otp-enrollment"
				match := regexp.MustCompile(`<code[^>]*>([A-Z2-7]+)</code>`).FindStringSubmatch(page.Body.String())
				if match == nil {
					t.Fatalf("missing other enrollment %s", page.Body)
				}
				secret = match[1]
			}
			if strings.Contains(page.Body.String(), "za-webauthn") {
				t.Fatal("platform was first proof")
			}
			rec = f.post(t, path, url.Values{"code": {otpAt(secret, *f.clock)}})
			if !existing {
				if rec.Code != 200 {
					t.Fatalf("other enrollment %d %s", rec.Code, rec.Body)
				}
				rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
			}
			if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "mfa-webauthn-platform-enrollment") {
				t.Fatalf("platform next %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			if _, err := f.st.MFA().PeekTicket(context.Background(), f.tn.ID, secrets.HashToken(raw), *f.clock); err != nil {
				t.Fatalf("ticket spent before platform %v", err)
			}
			page = f.page(t, "/u/mfa-webauthn-platform-enrollment")
			assertMandatoryPlatformControls(t, page)
			p := readPasskeyPage(t, page)
			key := webauthntest.New(webauthntest.Options{UV: true, Attachment: "platform"})
			rec = f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"challenge_id": {p.ChallengeID}, "credential": {string(registrationFromPage(t, p, key, "https://acme.example.test"))}})
			if rec.Code != 303 {
				t.Fatalf("platform registration %d %s", rec.Code, rec.Body)
			}
			page = f.page(t, "/u/mfa-webauthn-change-key-nickname")
			if strings.Contains(page.Body.String(), "action=another") {
				t.Fatal("platform nickname exposed broken alternate-method loop")
			}

			if !strings.Contains(page.Body.String(), `value="Browser on device"`) || !strings.Contains(page.Body.String(), "Name your authenticator") {
				t.Fatal("missing default name")
			}
			rec = f.post(t, "/u/mfa-webauthn-change-key-nickname", url.Values{"name": {"My device"}})
			if rec.Code != 303 {
				t.Fatalf("platform nickname %d %s", rec.Code, rec.Body)
			}
			if _, err := f.st.MFA().PeekTicket(context.Background(), f.tn.ID, secrets.HashToken(raw), *f.clock); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("ticket unspent %v", err)
			}
		})
	}
}

func TestPlatformRulesExplicitRequiresCapability(t *testing.T) {
	f := newRoamingMFAFixture(t)
	f.policy(t, "otp", "webauthn-platform")
	f.enrolled(t, "otp", false)
	raw := "platform-no-capability"
	if err := f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, UserID: f.uid, Hash: secrets.HashToken(raw), Factor: "webauthn-platform", ExpiresAt: f.clock.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rec := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa-detect-browser-capabilities")
	rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}, "platform": {"0"}})
	if rec.Code != 400 {
		t.Fatalf("explicit platform unavailable %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

func TestPlatformProgressiveEnrollmentSnoozeWindows(t *testing.T) {
	f := newRoamingMFAFixture(t)
	f.policy(t, "otp", "webauthn-platform")
	secret := f.enrolled(t, "otp", false)
	old := f.srv
	ua := "Mozilla/5.0 (Macintosh) Chrome/130.0 Safari/537.36"
	f.srv = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Header.Set("User-Agent", ua); old.ServeHTTP(w, r) })
	prove := func() *httptest.ResponseRecorder {
		*f.clock = f.clock.Add(time.Minute)
		refusal := f.b.cookies["za_platform_refuse"]
		f.b = f.env.browser("acme.example.test")
		if refusal != nil {
			f.b.cookies["za_platform_refuse"] = refusal
		}
		_, s, c := f.b.begin(t)
		rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
		loc, _ := url.Parse(rec.Header().Get("Location"))
		f.state = loc.Query().Get("state")
		f.page(t, "/u/mfa-detect-browser-capabilities")
		f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}, "platform": {"1"}})
		f.page(t, "/u/mfa")
		return f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	}
	expectOffer := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "platform-enrollment") {
			t.Fatalf("missing offer %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
	}
	expectComplete := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
			t.Fatalf("suppression %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
	}
	expectOffer(prove())
	f.page(t, "/u/mfa-webauthn-platform-enrollment")
	expectComplete(f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"platform_choice": {"remind"}}))
	expectComplete(prove())
	*f.clock = f.clock.Add(14 * 24 * time.Hour)
	expectOffer(prove())
	f.page(t, "/u/mfa-webauthn-platform-enrollment")
	expectComplete(f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"platform_choice": {"refuse"}}))
	cookie := f.b.cookies["za_platform_refuse"]
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.MaxAge != 365*24*60*60 || !cookie.Expires.Equal(f.clock.Add(365*24*time.Hour)) {
		t.Fatalf("refusal cookie %+v", cookie)
	}
	// Expire the durable copy to prove the independently authenticated cookie.
	if err := f.st.WebAuthn().PutSnooze(context.Background(), &store.WebAuthnSnooze{TenantID: f.tn.ID, UserID: f.uid, Kind: "platform-refuse", ScopeKey: "macos/chrome/desktop", Until: *f.clock}); err != nil {
		t.Fatal(err)
	}
	expectComplete(prove())
	ua = "Mozilla/5.0 (Macintosh) Firefox/130.0"
	expectOffer(prove())
	ua = "Mozilla/5.0 (Macintosh) Chrome/130.0 Safari/537.36"
	*f.clock = f.clock.Add(365 * 24 * time.Hour)
	expectOffer(prove())
}

func TestPlatformProgressiveEnrollmentAfterRecovery(t *testing.T) {
	for _, keepPrimary := range []bool{true, false} {
		t.Run(map[bool]string{true: "confirmed-OTP", false: "recovery-only"}[keepPrimary], func(t *testing.T) {
			f := newRoamingMFAFixture(t)
			f.policy(t, "otp", "webauthn-platform")
			f.enrolled(t, "otp", false)
			raw := mfa.NewRecoveryCode()
			ctx := context.Background()
			list, err := f.st.MFA().ListAuthenticators(ctx, f.tn.ID, f.uid)
			if err != nil {
				t.Fatal(err)
			}
			oldHash := ""
			for _, a := range list {
				if a.Type == "recovery-code" {
					oldHash = a.CodeHash
				}
			}
			if err := f.st.MFA().ReplaceRecoveryCode(ctx, f.tn.ID, f.uid, oldHash, secrets.HashToken(raw), *f.clock); err != nil {
				t.Fatal(err)
			}
			_, s, c := f.b.begin(t)
			rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
			loc, _ := url.Parse(rec.Header().Get("Location"))
			f.state = loc.Query().Get("state")
			f.page(t, "/u/mfa-detect-browser-capabilities")
			f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}, "platform": {"1"}})
			f.b.do(t, "GET", "/u/mfa?action=another&state="+f.state, nil)
			rec = f.post(t, "/u/mfa", url.Values{"factor": {"recovery-code"}})
			if rec.Code != 303 {
				t.Fatalf("select recovery %d %s", rec.Code, rec.Body)
			}
			f.page(t, "/u/mfa-recovery-code-challenge")
			rec = f.post(t, "/u/mfa-recovery-code-challenge", url.Values{"code": {raw}})
			if rec.Code != 200 {
				t.Fatalf("recovery proof %d %s", rec.Code, rec.Body)
			}
			if !keepPrimary {
				list, err := f.st.MFA().ListAuthenticators(ctx, f.tn.ID, f.uid)
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range list {
					if a.Type == "totp" {
						if err = f.st.MFA().DeleteAuthenticator(ctx, f.tn.ID, f.uid, a.ID); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
			if keepPrimary {
				if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "mfa-webauthn-platform-enrollment") {
					t.Fatalf("recovery progression %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
				}
			} else if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
				t.Fatalf("recovery-only completion %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
		})
	}
}

func beginPlatformAction(t *testing.T, call string, available, platform bool) *mfaFixture {
	t.Helper()
	f := newRoamingMFAFixture(t)
	f.policy(t, "otp", "email", "webauthn-platform")
	f.tn.SettingsExtra["customize_mfa_in_postlogin_action"] = true
	if err := f.st.Tenants().Update(context.Background(), f.tn); err != nil {
		t.Fatal(err)
	}
	a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
	f.h.Actions, f.h.Authz.Actions = a.Engine, a.Engine
	a.Bind(t, f.tn.ID, actions.TriggerPostLogin, a.Deploy(t, f.tn.ID, actions.TriggerPostLogin, "platform-choices", "exports.onExecutePostLogin=(event,api)=>api.authentication."+call+";"))
	_, s, c := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Path != "/u/mfa" {
		t.Fatalf("action gate %d %s %s", rec.Code, loc, rec.Body)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa-detect-browser-capabilities")
	value := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {value(available)}, "platform": {value(platform)}})
	if rec.Code != 303 {
		t.Fatalf("action detection %d %s", rec.Code, rec.Body)
	}
	return f
}

func TestPlatformActionEnrollmentAlternatives(t *testing.T) {
	for _, caps := range []struct {
		name                string
		available, platform bool
	}{
		{"available", true, true}, {"no-platform", true, false}, {"no-script", false, false},
	} {
		t.Run(caps.name, func(t *testing.T) {
			f := beginPlatformAction(t, "enrollWithAny([{type:'otp'},{type:'webauthn-platform'}])", caps.available, caps.platform)
			page := f.page(t, "/u/mfa")
			if caps.platform {
				for _, factor := range []string{"otp", "webauthn-platform"} {
					if !strings.Contains(page.Body.String(), `value="`+factor+`"`) {
						t.Fatalf("missing requested choice %s: %s", factor, page.Body)
					}
				}
				if strings.Contains(page.Body.String(), `value="email"`) {
					t.Fatal("unrequested email offered")
				}
				rec := f.post(t, "/u/mfa", url.Values{"factor": {"otp"}})
				if rec.Code != 303 {
					t.Fatalf("OTP choice %d %s", rec.Code, rec.Body)
				}
				page = f.page(t, "/u/mfa-otp-enrollment")
			}
			match := regexp.MustCompile(`<code[^>]*>([A-Z2-7]+)</code>`).FindStringSubmatch(page.Body.String())
			if match == nil {
				t.Fatalf("missing OTP enrollment %s", page.Body)
			}
			rec := f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(match[1], *f.clock)}})
			if rec.Code != 200 {
				t.Fatalf("OTP proof %d %s", rec.Code, rec.Body)
			}
			rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
			if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
				t.Fatalf("requested OTP must complete %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
		})
	}
}

func TestPlatformActionChoiceRequiresOtherProof(t *testing.T) {
	f := beginPlatformAction(t, "enrollWithAny([{type:'otp'},{type:'webauthn-platform'}])", true, true)
	f.page(t, "/u/mfa")
	rec := f.post(t, "/u/mfa", url.Values{"factor": {"webauthn-platform"}})
	if rec.Code != 303 || strings.Contains(rec.Header().Get("Location"), "platform-enrollment") {
		t.Fatalf("platform before other proof %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	page := f.page(t, "/u/mfa")
	// Another enabled factor may be used only after platform was chosen.
	if !strings.Contains(page.Body.String(), `value="otp"`) {
		t.Fatalf("missing prerequisite choice %s", page.Body)
	}
	rec = f.post(t, "/u/mfa", url.Values{"factor": {"otp"}})
	if rec.Code != 303 {
		t.Fatalf("other choice %d %s", rec.Code, rec.Body)
	}
	page = f.page(t, "/u/mfa-otp-enrollment")
	match := regexp.MustCompile(`<code[^>]*>([A-Z2-7]+)</code>`).FindStringSubmatch(page.Body.String())
	if match == nil {
		t.Fatalf("missing prerequisite OTP %s", page.Body)
	}
	rec = f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(match[1], *f.clock)}})
	if rec.Code != 200 {
		t.Fatalf("other proof %d %s", rec.Code, rec.Body)
	}
	rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "platform-enrollment") {
		t.Fatalf("platform after proof %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	page = f.page(t, "/u/mfa-webauthn-platform-enrollment")
	assertMandatoryPlatformControls(t, page)
	p := readPasskeyPage(t, page)
	key := webauthntest.New(webauthntest.Options{UV: true, Attachment: "platform"})
	rec = f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"challenge_id": {p.ChallengeID}, "credential": {string(registrationFromPage(t, p, key, "https://acme.example.test"))}})
	if rec.Code != 303 {
		t.Fatalf("selected platform registration %d %s", rec.Code, rec.Body)
	}
	f.page(t, "/u/mfa-webauthn-change-key-nickname")
	rec = f.post(t, "/u/mfa-webauthn-change-key-nickname", url.Values{"name": {"Selected device"}})
	if rec.Code != 303 {
		t.Fatalf("selected platform nickname %d %s", rec.Code, rec.Body)
	}
	f.page(t, "/u/mfa-webauthn-enrollment-success")
	rec = f.post(t, "/u/mfa-webauthn-enrollment-success", url.Values{})
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("selected platform completion %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

func assertMandatoryPlatformControls(t *testing.T, page *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(page.Body.String(), `name="platform_choice"`) {
		t.Fatal("mandatory enrollment exposed optional deferrals")
	}
	if !strings.Contains(page.Body.String(), `id="za-passkey-button" type="button">Continue</button>`) {
		t.Fatalf("missing enrollment continue control %s", page.Body)
	}
}

func TestPlatformMandatoryActionControls(t *testing.T) {
	f := beginPlatformAction(t, "enrollWith({type:'webauthn-platform'})", true, true)
	page := f.page(t, "/u/mfa")
	match := regexp.MustCompile(`<code[^>]*>([A-Z2-7]+)</code>`).FindStringSubmatch(page.Body.String())
	if match == nil {
		t.Fatalf("missing prerequisite OTP %s", page.Body)
	}
	rec := f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(match[1], *f.clock)}})
	if rec.Code != 200 {
		t.Fatalf("other proof %d %s", rec.Code, rec.Body)
	}
	rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if rec.Code != 303 {
		t.Fatalf("platform next %d %s", rec.Code, rec.Body)
	}
	assertMandatoryPlatformControls(t, f.page(t, "/u/mfa-webauthn-platform-enrollment"))
	rec = f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"platform_choice": {"skip"}})
	if rec.Code != 400 || strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("mandatory platform accepted deferral %d %s", rec.Code, rec.Body)
	}
}

func TestPlatformOptionalEnrollmentErrorControls(t *testing.T) {
	f := newRoamingMFAFixture(t)
	f.policy(t, "otp", "webauthn-platform")
	secret := f.enrolled(t, "otp", false)
	_, s, c := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa-detect-browser-capabilities")
	f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}, "platform": {"1"}})
	f.page(t, "/u/mfa")
	rec = f.post(t, "/u/mfa-otp-challenge", url.Values{"code": {otpAt(secret, *f.clock)}})
	if rec.Code != 303 {
		t.Fatalf("offer %d %s", rec.Code, rec.Body)
	}
	p := readPasskeyPage(t, f.page(t, "/u/mfa-webauthn-platform-enrollment"))
	rec = f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"challenge_id": {p.ChallengeID}, "webauthn_error": {"NotAllowedError"}})
	if rec.Code != 400 {
		t.Fatalf("cancellation %d %s", rec.Code, rec.Body)
	}
	for _, text := range []string{"Try security key again", "Remind me later", "Not on this device", "Not now"} {
		if !strings.Contains(rec.Body.String(), text) {
			t.Errorf("error page missing %q", text)
		}
	}
	if strings.Contains(rec.Body.String(), "mfa-webauthn.mfa-webauthn-error.") {
		t.Error("raw catalog key on platform error page")
	}
	// The optional controls are usable even after the canceled ceremony.
	rec = f.post(t, "/u/mfa-webauthn-platform-enrollment", url.Values{"platform_choice": {"skip"}})
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("error deferral %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}
