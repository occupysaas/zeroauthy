package login

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// hostedPhoneRunner backs a branding "custom" phone provider and captures
// the codes handed to the Action.
type hostedPhoneRunner struct {
	mu    sync.Mutex
	calls []phone.ActionInput
}

func (r *hostedPhoneRunner) PhoneActionBound(context.Context, string, string) (bool, error) {
	return true, nil
}
func (r *hostedPhoneRunner) RunPhoneAction(_ context.Context, _ string, in phone.ActionInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	return nil
}
func (r *hostedPhoneRunner) last(t *testing.T) phone.ActionInput {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("no phone message was sent")
	}
	return r.calls[len(r.calls)-1]
}
func (r *hostedPhoneRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

var hostedPhonePaths = []string{"/u/mfa-phone-enrollment", "/u/mfa-sms-challenge", "/u/mfa-voice-challenge"}

// newPhoneMFAFixture requires MFA by policy with the sms factor, the given
// message types and a working custom branding provider.
func newPhoneMFAFixture(t *testing.T, types ...string) (*mfaFixture, *hostedPhoneRunner) {
	t.Helper()
	f := newMFAFixture(t)
	r := &hostedPhoneRunner{}
	f.h.Authz.MFA = f.h.MFA
 f.h.MFA.Phone = &phone.Dispatcher{Store: f.st, Wrapper: f.h.Authz.Wrapper, Actions: r}
	f.policy(t, "sms")
	ctx := context.Background()
	g, err := f.st.MFA().GetGuardian(ctx, f.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	raw, _ := json.Marshal(map[string]any{"message_types": types})
	g.Stored["/guardian/factors/phone/message-types"] = raw
	if err = f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	if err = f.st.Phone().CreatePhoneProvider(ctx, &store.PhoneProvider{TenantID: f.tn.ID, ID: "pro_1", Name: "custom", Configuration: json.RawMessage(`{"delivery_methods":["text","voice"]}`)}); err != nil {
		t.Fatal(err)
	}
	old := f.srv
	mux := http.NewServeMux()
	for _, p := range hostedPhonePaths {
		mux.HandleFunc("GET "+p, f.h.MFAPage)
		mux.HandleFunc("POST "+p, f.h.MFASubmit)
	}
	mux.Handle("/", old)
	f.srv = tenant.NewResolver(f.st.Tenants(), "", false).Middleware(mux)
	return f, r
}

// enrolledPhone confirms a phone method for alice through the service.
func (f *mfaFixture) enrolledPhone(t *testing.T, r *hostedPhoneRunner, method string) {
	t.Helper()
	ctx := context.Background()
	e, err := f.h.MFA.BeginPhoneEnroll(ctx, f.tn.ID, f.uid, "+14155550100", method)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.MFA.ConfirmEnroll(ctx, f.tn.ID, f.uid, e, mfa.Proof{Code: r.last(t).Message.Code}); err != nil {
		t.Fatal(err)
	}
	*f.clock = f.clock.Add(time.Minute)
}

func (f *mfaFixture) location(t *testing.T, rec interface{ Header() http.Header }) string {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Path
}

func TestHostedSMSEnrollAndChallenge(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms")
	f.begin(t)
	p := f.page(t, "/u/mfa-phone-enrollment")
	body := p.Body.String()
	if !strings.Contains(body, `name="phone_number"`) || strings.Contains(body, `value="voice"`) {
		t.Fatalf("enrollment form %s", body)
	}
	// country_codes applies before anything is sent.
	f.tn.SettingsExtra["country_codes"] = map[string]any{"mode": "deny", "list": []any{"FR"}}
	if err := f.st.Tenants().Update(context.Background(), f.tn); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"+33612345678", "0612345678"} {
		rec := f.post(t, "/u/mfa-phone-enrollment", url.Values{"phone_number": {bad}})
		if rec.Code != 400 || r.count() != 0 {
			t.Fatalf("%s = %d sends=%d", bad, rec.Code, r.count())
		}
		f.page(t, "/u/mfa-phone-enrollment")
	}
	rec := f.post(t, "/u/mfa-phone-enrollment", url.Values{"phone_number": {"+1 415 555 0100"}})
	if rec.Code != 303 || f.location(t, rec) != "/u/mfa-sms-challenge" {
		t.Fatalf("enroll number = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	in := r.last(t)
	if in.Message.To != "+14155550100" || in.MessageType != "otp_enroll" || in.Message.DeliveryMethod != "text" {
		t.Fatalf("enrollment message %+v %s", in.Message, in.MessageType)
	}
	p = f.page(t, "/u/mfa-sms-challenge")
	if !strings.Contains(p.Body.String(), `name="code"`) || strings.Contains(p.Body.String(), "+14155550100") || !strings.Contains(p.Body.String(), "XXXXXXXX0100") {
		t.Fatalf("code page %s", p.Body)
	}
	rec = f.post(t, "/u/mfa-sms-challenge", url.Values{"code": {in.Message.Code}})
	recovery := regexp.MustCompile(`<code id="recovery-code">([A-Z0-9]{24})</code>`).FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || recovery == nil {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body)
	}
	f.page(t, "/u/mfa-recovery-code-enrollment")
	if rec = f.post(t, "/u/mfa-recovery-code-enrollment", url.Values{"ack": {"yes"}}); rec.Code != 302 {
		t.Fatalf("acknowledge = %d %s", rec.Code, rec.Body)
	}
	aa, _ := f.st.MFA().ListAuthenticators(context.Background(), f.tn.ID, f.uid)
	phones := 0
	for _, a := range aa {
		if a.Type == "phone" && a.Confirmed && a.Phone == "+14155550100" && a.PhoneMethod == "sms" {
			phones++
		}
	}
	if phones != 1 {
		t.Fatalf("methods %+v", aa)
	}

	// A later login challenges the enrolled phone by SMS.
	f2, r2 := newPhoneMFAFixture(t, "sms")
	f2.enrolledPhone(t, r2, "sms")
	sent := r2.count()
	f2.begin(t)
	if r2.count() != sent+1 || r2.last(t).MessageType != "otp_verify" || r2.last(t).Message.DeliveryMethod != "text" {
		t.Fatalf("challenge send %d %+v", r2.count()-sent, r2.last(t))
	}
	f2.page(t, "/u/mfa-sms-challenge")
	if rec = f2.post(t, "/u/mfa-sms-challenge", url.Values{"code": {"999999"}}); rec.Code != 400 {
		t.Fatalf("wrong code = %d", rec.Code)
	}
	f2.page(t, "/u/mfa-sms-challenge")
	// Resend waits 30 seconds, then sends a new code.
	if rec = f2.post(t, "/u/mfa-sms-challenge", url.Values{"action": {"resend"}}); rec.Code != 429 {
		t.Fatalf("early resend = %d", rec.Code)
	}
	*f2.clock = f2.clock.Add(30 * time.Second)
	f2.page(t, "/u/mfa-sms-challenge")
	if rec = f2.post(t, "/u/mfa-sms-challenge", url.Values{"action": {"resend"}}); rec.Code != 200 || r2.count() != sent+2 {
		t.Fatalf("resend = %d sends=%d", rec.Code, r2.count()-sent)
	}
	if rec = f2.post(t, "/u/mfa-sms-challenge", url.Values{"code": {r2.last(t).Message.Code}}); rec.Code != 302 {
		t.Fatalf("verify = %d %s", rec.Code, rec.Body)
	}
}

func TestHostedVoiceChallenge(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms", "voice")
	f.enrolledPhone(t, r, "voice")
	*f.clock = f.clock.Add(time.Hour)
	f.begin(t)
	in := r.last(t)
	if in.Message.DeliveryMethod != "voice" || in.MessageType != "otp_verify" {
		t.Fatalf("voice challenge %+v %s", in.Message, in.MessageType)
	}
	p := f.page(t, "/u/mfa-voice-challenge")
	if !strings.Contains(p.Body.String(), `name="code"`) {
		t.Fatalf("voice page %s", p.Body)
	}
	if rec := f.post(t, "/u/mfa-voice-challenge", url.Values{"code": {in.Message.Code}}); rec.Code != 302 {
		t.Fatalf("voice verify = %d %s", rec.Code, rec.Body)
	}
}

func TestHostedSwitchSMSVoice(t *testing.T) {
	f, r := newPhoneMFAFixture(t, "sms", "voice")
	f.enrolledPhone(t, r, "sms")
	f.begin(t)
	p := f.page(t, "/u/mfa-sms-challenge")
	if !strings.Contains(p.Body.String(), `value="switch"`) {
		t.Fatalf("no switch offered %s", p.Body)
	}
	rec := f.post(t, "/u/mfa-sms-challenge", url.Values{"action": {"switch"}})
	if rec.Code != 303 || f.location(t, rec) != "/u/mfa-voice-challenge" {
		t.Fatalf("switch = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	in := r.last(t)
	if in.Message.DeliveryMethod != "voice" {
		t.Fatalf("switch sent %+v", in.Message)
	}
	f.page(t, "/u/mfa-voice-challenge")
	if rec = f.post(t, "/u/mfa-voice-challenge", url.Values{"code": {in.Message.Code}}); rec.Code != 302 {
		t.Fatalf("verify after switch = %d %s", rec.Code, rec.Body)
	}

	// With only sms allowed there is nothing to switch to.
	f2, r2 := newPhoneMFAFixture(t, "sms")
	f2.enrolledPhone(t, r2, "sms")
	f2.begin(t)
	p = f2.page(t, "/u/mfa-sms-challenge")
	if strings.Contains(p.Body.String(), `value="switch"`) {
		t.Fatal("switch offered with one message type")
	}
	sent := r2.count()
	rec = f2.post(t, "/u/mfa-sms-challenge", url.Values{"action": {"switch"}})
	if r2.count() != sent || f2.location(t, rec) == "/u/mfa-voice-challenge" {
		t.Fatalf("switch without voice = %d sends=%d", rec.Code, r2.count()-sent)
	}
}
