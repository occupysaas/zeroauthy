package login

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthn"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
)

func newRoamingMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	f := newMFAFixture(t)
	f.h.Passkeys = passkey.NewService(f.st, rpid.Policy{}, f.h.Now)
	f.h.Authz.Passkeys = f.h.Passkeys
	f.h.Authz.MFA = f.h.MFA
	old := f.srv
	mux := http.NewServeMux()
	for _, p := range []string{"/u/mfa-detect-browser-capabilities", "/u/mfa-webauthn-roaming-enrollment", "/u/mfa-webauthn-roaming-challenge", "/u/mfa-webauthn-change-key-nickname", "/u/mfa-webauthn-enrollment-success"} {
		mux.HandleFunc("GET "+p, f.h.MFAPage)
		mux.HandleFunc("POST "+p, f.h.MFASubmit)
	}
	mux.Handle("/", old)
	f.srv = tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux)
	f.policy(t, "webauthn-roaming")
	return f
}
func (f *mfaFixture) startRoaming(t *testing.T, available bool) *httptest.ResponseRecorder {
	t.Helper()
	_, s, c := f.b.begin(t)
	rec := f.b.do(t, "POST", "/u/login", url.Values{"state": {s}, "csrf": {c}, "username": {aliceLogin}, "password": {"alice password 1"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/u/mfa" {
		t.Fatalf("gate %d %s %s", rec.Code, loc, rec.Body)
	}
	f.state = loc.Query().Get("state")
	rec = f.b.do(t, "GET", loc.RequestURI(), nil)
	if !strings.Contains(rec.Header().Get("Location"), "/u/mfa-detect-browser-capabilities?") {
		t.Fatalf("detect first %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	page := f.page(t, "/u/mfa-detect-browser-capabilities")
	if !strings.Contains(page.Body.String(), `name="webauthn" value="0"`) {
		t.Fatal("no-script fallback missing")
	}
	value := "0"
	if available {
		value = "1"
	}
	rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {value}, "platform": {"0"}})
	if !available {
		return rec
	}
	if rec.Code != 303 {
		t.Fatalf("detect submit %d %s", rec.Code, rec.Body)
	}
	rec = f.b.do(t, "GET", rec.Header().Get("Location"), nil)
	for i := 0; i < 2 && rec.Code == 303; i++ {
		rec = f.b.do(t, "GET", rec.Header().Get("Location"), nil)
	}
	if rec.Code != 200 {
		t.Fatalf("factor page %d %s", rec.Code, rec.Body)
	}
	if m := csrfField.FindStringSubmatch(rec.Body.String()); m != nil {
		f.csrf = m[1]
	}
	return rec
}
func TestHostedRoamingEnrollAndChallenge(t *testing.T) {
	f := newRoamingMFAFixture(t)
	page := f.startRoaming(t, true)
	p := readPasskeyPage(t, page)
	var options struct {
		Selection struct {
			Attachment string `json:"authenticatorAttachment"`
			Resident   string `json:"residentKey"`
			UV         string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	}
	if json.Unmarshal(p.Options, &options) != nil || options.Selection.Attachment != "cross-platform" || options.Selection.Resident != "discouraged" || options.Selection.UV != "discouraged" {
		t.Fatalf("options %s", p.Options)
	}
	key := webauthntest.New(webauthntest.Options{Attachment: "cross-platform", OmitUserHandle: true})
	raw := registrationFromPage(t, p, key, "https://acme.example.test")
	rec := f.post(t, "/u/mfa-webauthn-roaming-enrollment", url.Values{"challenge_id": {p.ChallengeID}, "credential": {string(raw)}, "remember": {"yes"}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "change-key-nickname") {
		t.Fatalf("registration %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	f.page(t, "/u/mfa-webauthn-change-key-nickname")
	for _, name := range []string{"", strings.Repeat("a", 21)} {
		rec = f.post(t, "/u/mfa-webauthn-change-key-nickname", url.Values{"name": {name}})
		if rec.Code != 400 {
			t.Fatalf("nickname %q = %d %s", name, rec.Code, rec.Body)
		}
	}
	rec = f.post(t, "/u/mfa-webauthn-change-key-nickname", url.Values{"name": {"Travel key"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="ack"`) {
		t.Fatalf("recovery %d %s", rec.Code, rec.Body)
	}
	rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}})
	if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "enrollment-success") {
		t.Fatalf("success %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	f.page(t, "/u/mfa-webauthn-enrollment-success")
	rec = f.post(t, "/u/mfa-webauthn-enrollment-success", url.Values{})
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("completion %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	methods, err := f.st.MFA().ListAuthenticators(context.Background(), f.tn.ID, f.uid)
	if err != nil || len(methods) != 2 {
		t.Fatalf("methods %+v %v", methods, err)
	}
	var enrolled store.Authenticator
	for _, a := range methods {
		if a.Type == "webauthn-roaming" {
			enrolled = a
		}
	}
	if enrolled.Name != "Travel key" || !enrolled.Confirmed {
		t.Fatalf("method %+v", enrolled)
	}
	// A fresh browser must challenge with only this user's current RP key.
	f.b = f.env.browser("acme.example.test")
	page = f.startRoaming(t, true)
	// The factor choice offers recovery alongside the security key.
	if strings.Contains(page.Body.String(), `value="webauthn-roaming"`) {
		if !strings.Contains(page.Body.String(), `value="recovery-code"`) {
			t.Fatal("recovery absent from other methods")
		}
		rec = f.post(t, "/u/mfa", url.Values{"factor": {"webauthn-roaming"}})
		page = f.b.do(t, "GET", rec.Header().Get("Location"), nil)
	}
	another := f.b.do(t, "GET", "/u/mfa?action=another&state="+f.state, nil)
	if !strings.Contains(another.Body.String(), `value="recovery-code"`) {
		t.Fatal("try another method omitted recovery")
	}
	// Returning from the factor list renders the current form before submission.
	page = f.page(t, "/u/mfa-webauthn-roaming-challenge")
	p = readPasskeyPage(t, page)
	var request struct {
		Challenge, RPID string
		Allow           []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err = json.Unmarshal(p.Options, &request); err != nil {
		t.Fatal(err)
	}
	// rpId does not match the Go field RPID through json's case matching.
	var wire map[string]json.RawMessage
	_ = json.Unmarshal(p.Options, &wire)
	_ = json.Unmarshal(wire["rpId"], &request.RPID)
	if len(request.Allow) != 1 {
		t.Fatalf("allow list %s", p.Options)
	}
	assertion := key.Get(webauthn.RequestOptions{RPID: request.RPID, Challenge: decode64(t, request.Challenge), Allow: []webauthn.Descriptor{{ID: decode64(t, request.Allow[0].ID)}}}, "https://acme.example.test")
	rec = f.post(t, "/u/mfa-webauthn-roaming-challenge", url.Values{"challenge_id": {p.ChallengeID}, "credential": {string(assertion)}, "remember": {"yes"}})
	if rec.Code != 302 || !strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("assertion %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	remembered := false
	for _, c := range rec.Result().Cookies() {
		remembered = remembered || strings.Contains(c.Name, "mfa") && c.MaxAge >= 0
	}
	if !remembered {
		t.Fatal("remember browser cookie absent")
	}
}
func TestHostedWebAuthnNoScript(t *testing.T) {
	for _, alternate := range []bool{false, true} {
		t.Run(map[bool]string{false: "only-key", true: "otp"}[alternate], func(t *testing.T) {
			f := newRoamingMFAFixture(t)
			if alternate {
				f.policy(t, "otp", "webauthn-roaming")
			}
			rec := f.startRoaming(t, false)
			if alternate {
				if rec.Code != 303 {
					t.Fatalf("alternative %d %s", rec.Code, rec.Body)
				}
				page := f.page(t, "/u/mfa")
				if strings.Contains(page.Body.String(), `value="webauthn-roaming"`) {
					t.Fatal("unavailable key offered")
				}
			} else {
				if rec.Code != 400 || !strings.Contains(rec.Body.String(), "cannot use a security key") {
					t.Fatalf("unavailable %d %s", rec.Code, rec.Body)
				}
				rec = f.b.do(t, "GET", "/u/mfa?state="+f.state, nil)
				if rec.Code == 303 {
					t.Fatal("negative result looped into detection")
				}
			}
		})
	}
}
func TestWebAuthnEnrollmentTicket(t *testing.T) {
	f := newRoamingMFAFixture(t)
	raw := "roaming-ticket"
	if err := f.st.MFA().CreateTicket(context.Background(), &store.EnrollmentTicket{TenantID: f.tn.ID, UserID: f.uid, Hash: secrets.HashToken(raw), Factor: "webauthn-roaming", ExpiresAt: f.clock.Add(hostedPasskeyLifetime)}); err != nil {
		t.Fatal(err)
	}
	rec := f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	if rec.Code != 303 {
		t.Fatalf("ticket %d %s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa-detect-browser-capabilities")
	rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}})
	if rec.Code != 303 {
		t.Fatalf("detect %d %s", rec.Code, rec.Body)
	}
	page := f.page(t, "/u/mfa")
	p := readPasskeyPage(t, page)
	key := webauthntest.New(webauthntest.Options{})
	rec = f.post(t, "/u/mfa-webauthn-roaming-enrollment", url.Values{"challenge_id": {p.ChallengeID}, "credential": {string(registrationFromPage(t, p, key, "https://acme.example.test"))}})
	if rec.Code != 303 {
		t.Fatalf("registration %d %s", rec.Code, rec.Body)
	}
	f.page(t, "/u/mfa-webauthn-change-key-nickname")
	rec = f.post(t, "/u/mfa-webauthn-change-key-nickname", url.Values{"name": {"Ticket key"}})
	if rec.Code != 200 {
		t.Fatalf("nickname %d %s", rec.Code, rec.Body)
	}
	if _, err := f.st.MFA().PeekTicket(context.Background(), f.tn.ID, secrets.HashToken(raw), *f.clock); err == nil {
		t.Fatal("ticket was not consumed with insertion")
	}
	rec = f.b.do(t, "GET", "/u/mfa-enroll-ticket?ticket="+raw, nil)
	if rec.Code != 400 {
		t.Fatalf("ticket replay %d %s", rec.Code, rec.Body)
	}
}

func TestResetPostChallengeWebAuthn(t *testing.T) {
	f := newRoamingMFAFixture(t)
	ctx := context.Background()
	rp := rpid.Result{Valid: true, RPID: "acme.example.test", Origin: "https://acme.example.test"}
	svc := f.h.MFA.WithWebAuthnBinding(passkey.Binding{RPID: rp.RPID, Origins: []string{rp.Origin}, TxnID: "setup", CookieHash: "setup"})
	e, o, err := svc.BeginWebAuthnEnroll(ctx, f.tn.ID, f.uid, "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{})
	if _, err = svc.ConfirmWebAuthnEnroll(ctx, f.tn.ID, f.uid, e, key.Create(o, rp.Origin), "Key", "ua"); err != nil {
		t.Fatal(err)
	}
	tn, _ := f.st.Tenants().Get(ctx, f.tn.ID)
	tn.SettingsExtra = map[string]any{"customize_mfa_in_postlogin_action": true}
	if err = f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	a := actionstest.NewOffline(t, f.st, f.h.Authz.Wrapper)
	f.h.Actions = a.Engine
	a.Bind(t, tn.ID, actions.TriggerResetPostChallenge, a.Deploy(t, tn.ID, actions.TriggerResetPostChallenge, "reset-roaming", `exports.onExecutePostChallenge=(event,api)=>api.authentication.challengeWith({type:'webauthn-roaming'});`))
	raw := f.issueTicket(t, aliceLogin, time.Hour)
	rec := f.b.do(t, "GET", "/u/reset-password?ticket="+raw, nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 303 || loc.Path != "/u/mfa" {
		t.Fatalf("reset MFA %d %s %s", rec.Code, loc, rec.Body)
	}
	f.state = loc.Query().Get("state")
	f.page(t, "/u/mfa-detect-browser-capabilities")
	rec = f.post(t, "/u/mfa-detect-browser-capabilities", url.Values{"webauthn": {"1"}})
	if rec.Code != 303 {
		t.Fatalf("detect %d %s", rec.Code, rec.Body)
	}
	page := f.page(t, "/u/mfa")
	if !strings.Contains(page.Body.String(), "Verify your reset with a security key") {
		t.Fatalf("reset screen %s", page.Body)
	}
	p := readPasskeyPage(t, page)
	var request struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		Allow     []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	}
	if err = json.Unmarshal(p.Options, &request); err != nil {
		t.Fatal(err)
	}
	assertion := key.Get(webauthn.RequestOptions{RPID: request.RPID, Challenge: decode64(t, request.Challenge), Allow: []webauthn.Descriptor{{ID: decode64(t, request.Allow[0].ID)}}}, rp.Origin)
	rec = f.post(t, "/u/mfa-webauthn-roaming-challenge", url.Values{"challenge_id": {p.ChallengeID}, "credential": {string(assertion)}})
	loc, _ = url.Parse(rec.Header().Get("Location"))
	if rec.Code != 303 || loc.Path != "/u/reset-password" {
		t.Fatalf("reset proof %d %s %s", rec.Code, loc, rec.Body)
	}
	tk, err := f.st.PasswordResetTickets().GetByTokenHash(ctx, tn.ID, secrets.HashToken(raw))
	if err != nil || tk.ChallengePassedAt == nil || tk.UsedAt != nil {
		t.Fatalf("reset ticket %+v %v", tk, err)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "za_session" {
			t.Fatal("reset proof created SSO")
		}
	}
}

func TestHostedWebAuthnThrottle(t *testing.T) {
	f := newRoamingMFAFixture(t)
	ctx := context.Background()
	rp := rpid.Result{Valid: true, RPID: "acme.example.test", Origin: "https://acme.example.test"}
	svc := f.h.MFA.WithWebAuthnBinding(passkey.Binding{RPID: rp.RPID, Origins: []string{rp.Origin}, TxnID: "setup", CookieHash: "setup"})
	e, o, err := svc.BeginWebAuthnEnroll(ctx, f.tn.ID, f.uid, "webauthn-roaming", rp, passkey.UserDisplay{})
	if err != nil {
		t.Fatal(err)
	}
	key := webauthntest.New(webauthntest.Options{})
	if _, err = svc.ConfirmWebAuthnEnroll(ctx, f.tn.ID, f.uid, e, key.Create(o, rp.Origin), "Key", "ua"); err != nil {
		t.Fatal(err)
	}
	page := f.startRoaming(t, true)
	for i := 1; i <= 11; i++ {
		p := readPasskeyPage(t, page)
		page = f.post(t, "/u/mfa-webauthn-roaming-challenge", url.Values{"challenge_id": {p.ChallengeID}, "webauthn_error": {"NotAllowedError"}})
		want := 400
		if i == 11 {
			want = 429
		}
		if page.Code != want {
			t.Fatalf("attempt %d: status=%d want=%d body=%s", i, page.Code, want, page.Body)
		}
		if !strings.Contains(page.Body.String(), "Security key verification failed") {
			t.Fatal("error screen text did not render")
		}
		if i == 11 && !strings.Contains(page.Body.String(), "too many security key attempts") {
			t.Fatal("WebAuthn throttle text absent")
		}
		if m := csrfField.FindStringSubmatch(page.Body.String()); m != nil {
			f.csrf = m[1]
		}
	}
}

func TestHostedWebAuthnForeignKeyAllowsOTPEnrollment(t *testing.T) {
	f := newRoamingMFAFixture(t)
	f.policy(t, "otp", "webauthn-roaming")
	ctx := context.Background()
	old := &store.Authenticator{TenantID: f.tn.ID, UserID: f.uid, ID: mfa.NewMethodID("webauthn-roaming"), Type: "webauthn-roaming", Confirmed: true, RPID: "foreign.test", CredentialID: []byte{1}, PublicKey: []byte{1}}
	if err := f.st.MFA().CreateAuthenticator(ctx, old); err != nil {
		t.Fatal(err)
	}
	f.startRoaming(t, true)
	rec := f.post(t, "/u/mfa", url.Values{"factor": {"otp"}})
	if rec.Code != 303 {
		t.Fatalf("choose OTP %d %s", rec.Code, rec.Body)
	}
	f.page(t, "/u/mfa-otp-enrollment")
	aa, err := f.st.MFA().ListAuthenticators(ctx, f.tn.ID, f.uid)
	if err != nil {
		t.Fatal(err)
	}
	var secret string
	for _, a := range aa {
		if a.Type == "totp" && !a.Confirmed {
			e, err := f.h.MFA.EnrollmentDisplay(ctx, f.tn.ID, f.uid, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			secret = e.Secret
		}
	}
	rec = f.post(t, "/u/mfa-otp-enrollment", url.Values{"code": {otpAt(secret, *f.clock)}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="ack"`) {
		t.Fatalf("foreign key blocked OTP enrollment %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}
