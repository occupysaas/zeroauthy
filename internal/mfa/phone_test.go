package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// phoneRunner stands in for the Actions engine behind a branding "custom"
// provider: it captures each MFA code the dispatcher hands to the Action.
type phoneRunner struct {
	mu    sync.Mutex
	bound bool
	calls []phone.ActionInput
	err   error
}

func (r *phoneRunner) PhoneActionBound(context.Context, string, string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bound, nil
}
func (r *phoneRunner) RunPhoneAction(_ context.Context, _ string, in phone.ActionInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	return r.err
}
func (r *phoneRunner) last(t *testing.T) phone.ActionInput {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("no phone message was sent")
	}
	return r.calls[len(r.calls)-1]
}
func (r *phoneRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

type phoneFixture struct {
	*serviceFixture
	runner *phoneRunner
}

func newPhoneFixture(t *testing.T) *phoneFixture {
	t.Helper()
	f := &phoneFixture{serviceFixture: newServiceFixture(t), runner: &phoneRunner{bound: true}}
	f.svc.Phone = &phone.Dispatcher{Store: f.st, Wrapper: f.w, Actions: f.runner}
	f.guardian(t, func(g *store.GuardianSettings) { g.Factors["sms"] = true })
	return f
}
func (f *phoneFixture) guardian(t *testing.T, fn func(*store.GuardianSettings)) {
	t.Helper()
	g, err := f.st.MFA().GetGuardian(f.ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	fn(g)
	if err = f.st.MFA().PutGuardian(f.ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
}
func (f *phoneFixture) messageTypes(t *testing.T, types ...string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"message_types": types})
	f.guardian(t, func(g *store.GuardianSettings) { g.Stored["/guardian/factors/phone/message-types"] = raw })
}

// provider replaces the tenant's branding phone provider. Credentials are
// opaque here: only their presence matters until a native send.
func (f *phoneFixture) provider(t *testing.T, name, cfg string) {
	t.Helper()
	p := &store.PhoneProvider{TenantID: "tenant", ID: "pro_1", Name: name, Configuration: json.RawMessage(cfg)}
	if name != "custom" {
		p.SealedCredentials = []byte("sealed")
	}
	list, _ := f.st.Phone().ListPhoneProviders(f.ctx, "tenant")
	var err error
	if len(list) > 0 {
		err = f.st.Phone().UpdatePhoneProvider(f.ctx, p)
	} else {
		err = f.st.Phone().CreatePhoneProvider(f.ctx, p)
	}
	if err != nil {
		t.Fatal(err)
	}
}
func (f *phoneFixture) methods(t *testing.T) []string {
	t.Helper()
	m, err := f.svc.PhoneMethods(f.ctx, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPhoneFactorOfferedOnlyWithWorkingProvider(t *testing.T) {
	f := newPhoneFixture(t)
	decide := func() Requirement {
		t.Helper()
		g, _ := f.st.MFA().GetGuardian(f.ctx, "tenant")
		g.Policies = []string{"all-applications"}
		u, _ := f.st.Users().Get(f.ctx, "tenant", "user")
		aa, _ := f.st.MFA().ListAuthenticators(f.ctx, "tenant", "user")
		methods, err := f.svc.PhoneMethods(f.ctx, "tenant")
		if err != nil {
			t.Fatal(err)
		}
		r, err := Decide(DecideInput{Settings: g, User: u, Authenticators: aa, PhoneEnroll: len(methods) > 0})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// No provider at all: Guardian "auth0" routes to the branding provider.
	if m := f.methods(t); len(m) != 0 {
		t.Fatalf("offered without provider: %v", m)
	}
	if r := decide(); slices.Contains(r.Factors, "phone") {
		t.Fatalf("enrollment offered phone without provider: %+v", r)
	}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "sms"); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("enroll without provider = %v", err)
	}
	// A custom provider works only with a bound Action.
	f.runner.bound = false
	f.provider(t, "custom", `{"delivery_methods":["text","voice"]}`)
	if m := f.methods(t); len(m) != 0 {
		t.Fatalf("offered with unbound custom provider: %v", m)
	}
	f.runner.bound = true
	if m := f.methods(t); !slices.Equal(m, []string{"sms"}) {
		t.Fatalf("default message types = %v", m)
	}
	f.messageTypes(t, "sms", "voice")
	if m := f.methods(t); !slices.Equal(m, []string{"sms", "voice"}) {
		t.Fatalf("both message types = %v", m)
	}
	if r := decide(); !r.Enroll || !slices.Contains(r.Factors, "phone") {
		t.Fatalf("phone not offered with a working provider: %+v", r)
	}
	// The sms factor toggle still gates the phone factor.
	f.guardian(t, func(g *store.GuardianSettings) { g.Factors["sms"] = false })
	if m := f.methods(t); len(m) != 0 {
		t.Fatalf("offered with sms factor disabled: %v", m)
	}
	f.guardian(t, func(g *store.GuardianSettings) { g.Factors["sms"] = true })

	e, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+1 (415) 555-0100", "sms")
	if err != nil {
		t.Fatal(err)
	}
	in := f.runner.last(t)
	if in.Message.To != "+14155550100" || in.Message.DeliveryMethod != "text" || in.MessageType != "otp_enroll" || len(in.Message.Code) != 6 {
		t.Fatalf("enrollment message = %+v type=%s", in.Message, in.MessageType)
	}
	// Review Focus 5: the operator switches to SNS while the code is
	// outstanding. The code stays valid; voice is no longer offered.
	f.provider(t, "sns", `{"region":"us-east-1","delivery_methods":["text"]}`)
	if m := f.methods(t); !slices.Equal(m, []string{"sms"}) {
		t.Fatalf("sns methods = %v", m)
	}
	c, err := f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: in.Message.Code})
	if err != nil || c.RecoveryCode == "" {
		t.Fatalf("outstanding code after provider switch: %v", err)
	}
	a, err := f.st.MFA().GetAuthenticator(f.ctx, "tenant", "user", e.AuthenticatorID)
	if err != nil || a.Type != "phone" || a.Phone != "+14155550100" || a.PhoneMethod != "sms" || !a.Confirmed {
		t.Fatalf("authenticator = %+v %v", a, err)
	}
	// The provider is deleted: new enrollment is not offered, but the
	// enrolled user is still challenged (never silently skipped) and the
	// send fails closed with the documented code.
	if err = f.st.Phone().DeletePhoneProvider(f.ctx, "tenant", "pro_1"); err != nil {
		t.Fatal(err)
	}
	if m := f.methods(t); len(m) != 0 {
		t.Fatalf("offered after provider deletion: %v", m)
	}
	if r := decide(); r.Enroll || !slices.Equal(r.Factors, []string{"phone", "recovery-code"}) {
		t.Fatalf("enrolled user requirement after deletion: %+v", r)
	}
	before := f.events.count("gd_send_sms_failure")
	if _, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, ""); !errors.Is(err, ErrPhoneDelivery) {
		t.Fatalf("challenge without provider = %v", err)
	}
	if f.events.count("gd_send_sms_failure") != before+1 {
		t.Fatal("missing gd_send_sms_failure")
	}
}

func TestSNSVoiceUnavailable(t *testing.T) {
	f := newPhoneFixture(t)
	f.messageTypes(t, "sms", "voice")
	f.provider(t, "sns", `{"region":"us-east-1","delivery_methods":["text","voice"]}`)
	if m := f.methods(t); !slices.Equal(m, []string{"sms"}) {
		t.Fatalf("sns offers %v", m)
	}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "voice"); !errors.Is(err, ErrNoFactor) {
		t.Fatalf("voice enrollment through sns = %v", err)
	}
	// A provider configured for text only never offers voice either.
	f.provider(t, "custom", `{"delivery_methods":["text"]}`)
	if m := f.methods(t); !slices.Equal(m, []string{"sms"}) {
		t.Fatalf("text-only custom offers %v", m)
	}
}

func TestEnrollCountryCodes(t *testing.T) {
	f := newPhoneFixture(t)
	f.provider(t, "custom", `{"delivery_methods":["text"]}`)
	tn, _ := f.st.Tenants().Get(f.ctx, "tenant")
	tn.SettingsExtra = map[string]any{"country_codes": map[string]any{"mode": "deny", "list": []any{"US"}}}
	if err := f.st.Tenants().Update(f.ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "sms"); !errors.Is(err, ErrCountryNotAllowed) {
		t.Fatalf("denied country = %v", err)
	}
	for _, bad := range []string{"", "4155550100", "+1415abc0100", "+12"} {
		if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", bad, "sms"); !errors.Is(err, ErrInvalidPhone) {
			t.Fatalf("%q = %v", bad, err)
		}
	}
	if f.runner.count() != 0 {
		t.Fatal("a refused number was messaged")
	}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+44 7700 900123", "sms"); err != nil {
		t.Fatalf("allowed country: %v", err)
	}
	tn.SettingsExtra = map[string]any{"country_codes": map[string]any{"mode": "allow", "list": []any{"US"}}}
	if err := f.st.Tenants().Update(f.ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+447700900123", "sms"); !errors.Is(err, ErrCountryNotAllowed) {
		t.Fatalf("outside allow list = %v", err)
	}
}

func TestSendFailureLogsGdSendSMSFailure(t *testing.T) {
	f := newPhoneFixture(t)
	f.messageTypes(t, "sms", "voice")
	f.provider(t, "custom", `{"delivery_methods":["text","voice"]}`)
	f.runner.err = &phone.SendError{Class: phone.ClassTransient, Err: errors.New("runner down")}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "sms"); !errors.Is(err, ErrPhoneDelivery) {
		t.Fatalf("sms failure = %v", err)
	}
	if f.events.count("gd_send_sms_failure") != 1 || f.events.count("gd_send_sms") != 0 {
		t.Fatalf("events = %+v", f.events.events)
	}
	if list, _ := f.st.MFA().ListAuthenticators(f.ctx, "tenant", "user"); len(list) != 0 {
		t.Fatalf("failed enrollment kept a method: %+v", list)
	}
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "voice"); !errors.Is(err, ErrPhoneDelivery) {
		t.Fatalf("voice failure = %v", err)
	}
	if f.events.count("gd_send_voice_failure") != 1 {
		t.Fatal("missing gd_send_voice_failure")
	}
	f.runner.err = nil
	f.now = f.now.Add(time.Hour) // Failed delivery spends the voice send budget.
	if _, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "voice"); err != nil {
		t.Fatal(err)
	}
	if f.events.count("gd_send_voice") != 1 {
		t.Fatal("missing gd_send_voice")
	}
	code := f.runner.last(t).Message.Code
	// Neither the code (in any spoken form) nor the number reaches events.
	raw, _ := json.Marshal(f.events.events)
	for _, form := range append(phone.CodeForms(code), "+14155550100", "4155550100") {
		if strings.Contains(string(raw), form) {
			t.Fatalf("event leaked %q: %s", form, raw)
		}
	}
	if strings.Contains(f.output.String(), code) {
		t.Fatal("log leaked code")
	}
}

func TestPhoneThrottleShared(t *testing.T) {
	f := newPhoneFixture(t)
	f.messageTypes(t, "sms", "voice")
	f.provider(t, "custom", `{"delivery_methods":["text","voice"]}`)
	e, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "sms")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.ConfirmEnroll(f.ctx, "tenant", "user", e, Proof{Code: f.runner.last(t).Message.Code}); err != nil {
		t.Fatal(err)
	}
	// Ten sends per user per hour, whichever entry point asks (hosted pages
	// and the MFA API both call the same service with the same keys).
	for i := 1; i < 10; i++ {
		if _, err = f.svc.BeginPhoneChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "sms"); err != nil {
			t.Fatalf("send %d: %v", i+1, err)
		}
	}
	sent := f.runner.count()
	if _, err = f.svc.BeginChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, ""); !errors.Is(err, ErrThrottled) || !errors.Is(err, ErrSendLimit) {
		t.Fatalf("11th send = %v", err)
	}
	if f.runner.count() != sent || f.events.count("limit_phone") != 1 {
		t.Fatalf("budget: sent=%d limit_phone=%d", f.runner.count()-sent, f.events.count("limit_phone"))
	}
	// Another user has an independent budget.
	if err = f.st.MFA().CreateAuthenticator(f.ctx, &store.Authenticator{TenantID: "tenant", UserID: "other", ID: NewMethodID("phone"), Type: "phone", Phone: "+14155550199", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	list, _ := f.st.MFA().ListAuthenticators(f.ctx, "tenant", "other")
	if _, err = f.svc.BeginPhoneChallenge(f.ctx, "tenant", "other", list[0].ID, "sms"); err != nil {
		t.Fatalf("other user: %v", err)
	}
}

func TestPhoneVoiceOncePerHour(t *testing.T) {
	f := newPhoneFixture(t)
	f.messageTypes(t, "sms", "voice")
	f.provider(t, "custom", `{"delivery_methods":["text","voice"]}`)
	e, err := f.svc.BeginPhoneEnroll(f.ctx, "tenant", "user", "+14155550100", "voice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.BeginPhoneChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "voice"); !errors.Is(err, ErrSendLimit) {
		t.Fatalf("second voice request = %v", err)
	}
	if _, err = f.svc.BeginPhoneChallenge(f.ctx, "tenant", "user", e.AuthenticatorID, "sms"); err != nil {
		t.Fatalf("sms after voice: %v", err)
	}
	var limited *logs.Event
	for i := range f.events.events {
		if f.events.events[i].Type == "limit_phone" {
			limited = &f.events.events[i]
		}
	}
	if limited == nil || limited.Details["delivery_method"] != "voice" {
		t.Fatalf("limit_phone event = %+v", limited)
	}
}
