package oauth

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// mfaPhoneRunner backs a branding "custom" phone provider and captures the
// codes the dispatcher hands to the Action.
type mfaPhoneRunner struct {
	mu    sync.Mutex
	calls []phone.ActionInput
}

func (r *mfaPhoneRunner) PhoneActionBound(context.Context, string, string) (bool, error) {
	return true, nil
}
func (r *mfaPhoneRunner) RunPhoneAction(_ context.Context, _ string, in phone.ActionInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	return nil
}
func (r *mfaPhoneRunner) last(t *testing.T) phone.ActionInput {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("no phone message was sent")
	}
	return r.calls[len(r.calls)-1]
}
func (r *mfaPhoneRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// mfaPhoneFixture enables the sms factor with sms+voice message types and a
// working custom branding provider.
func mfaPhoneFixture(t *testing.T) (*fixture, *mfaPhoneRunner) {
	t.Helper()
	f, _ := mfaFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	g, err := f.st.MFA().GetGuardian(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	g.Factors["sms"] = true
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	g.Stored["/guardian/factors/phone/message-types"] = json.RawMessage(`{"message_types":["sms","voice"]}`)
	if err = f.st.MFA().PutGuardian(ctx, g, g.Version); err != nil {
		t.Fatal(err)
	}
	if err = f.st.Phone().CreatePhoneProvider(ctx, &store.PhoneProvider{TenantID: tid, ID: "pro_1", Name: "custom", Configuration: json.RawMessage(`{"delivery_methods":["text","voice"]}`)}); err != nil {
		t.Fatal(err)
	}
	r := &mfaPhoneRunner{}
	f.h.MFA.Phone = &phone.Dispatcher{Store: f.st, Wrapper: f.wrapper, Actions: r}
	return f, r
}

// enrollPhone confirms a phone method for alice through the service.
func (f *fixture) enrollPhone(t *testing.T, r *mfaPhoneRunner) string {
	t.Helper()
	ctx := context.Background()
	e, err := f.h.MFA.BeginPhoneEnroll(ctx, f.tenantID(t, "acme"), f.aliceID(t), "+14155550100", "sms")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.MFA.ConfirmEnroll(ctx, f.tenantID(t, "acme"), f.aliceID(t), e, mfa.Proof{Code: r.last(t).Message.Code}); err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(e.AuthenticatorID, "phone|")
}
func (f *fixture) phoneChallenge(t *testing.T, tok, authenticator string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"mfa_token": tok, "client_id": "ropg", "client_secret": "ropg-secret", "challenge_type": "oob", "authenticator_id": authenticator})
	w, b := f.mfaAPI(t, "POST", "/mfa/challenge", "", string(body))
	return w.Code, b
}

func TestMFAAssociateOOBSMS(t *testing.T) {
	f, r := mfaPhoneFixture(t)
	tok := f.mfaRequired(t)
	for _, tc := range []struct{ body, want string }{
		{`{"authenticator_types":["oob"],"oob_channels":["sms"]}`, "invalid_request"},
		{`{"authenticator_types":["oob"],"oob_channels":["sms"],"phone_number":"not a number"}`, "invalid_request"},
		{`{"authenticator_types":["oob"],"oob_channels":["auth0"],"phone_number":"+14155550100"}`, "invalid_request"},
	} {
		if w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, tc.body); w.Code != 400 || b["error"] != tc.want {
			t.Fatalf("%s = %d %v", tc.body, w.Code, b)
		}
	}
	if r.count() != 0 {
		t.Fatal("a refused association sent a message")
	}
	w, b := f.mfaAPI(t, "POST", "/mfa/associate", tok, `{"authenticator_types":["oob"],"oob_channels":["sms"],"phone_number":"+14155550100"}`)
	codes, _ := b["recovery_codes"].([]any)
	if w.Code != 200 || b["authenticator_type"] != "oob" || b["oob_channel"] != "sms" || b["binding_method"] != "prompt" || b["oob_code"] == "" || len(codes) != 1 {
		t.Fatalf("associate = %d %v", w.Code, b)
	}
	in := r.last(t)
	if in.Message.To != "+14155550100" || in.Message.DeliveryMethod != "text" || in.MessageType != "otp_enroll" {
		t.Fatalf("enrollment message = %+v %s", in.Message, in.MessageType)
	}
	form := mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", in.Message.Code)
	w, b = f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	if w.Code != 200 || b["access_token"] == nil || b["recovery_code"] != nil {
		t.Fatalf("mfa-oob enrollment grant = %d %v", w.Code, b)
	}
	// One phone enrollment is listed as sms|dev_X and voice|dev_X with the
	// masked number as its name.
	tok = f.mfaRequired(t)
	w, _ = f.mfaAPI(t, "GET", "/mfa/authenticators", tok, "")
	var list []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	byID := map[string]map[string]any{}
	for _, a := range list {
		byID[a["id"].(string)] = a
	}
	var suffix string
	for id := range byID {
		if strings.HasPrefix(id, "sms|dev_") {
			suffix = strings.TrimPrefix(id, "sms|")
		}
	}
	sms, voice := byID["sms|"+suffix], byID["voice|"+suffix]
	if sms == nil || voice == nil || sms["authenticator_type"] != "oob" || sms["oob_channel"] != "sms" || voice["oob_channel"] != "voice" || sms["name"] != "XXXXXXXX0100" || sms["active"] != true {
		t.Fatalf("authenticators = %s", w.Body)
	}
	if strings.Contains(w.Body.String(), "+14155550100") {
		t.Fatal("authenticator list leaked the number")
	}
}

func TestMFAChallengeOOBVoice(t *testing.T) {
	f, r := mfaPhoneFixture(t)
	suffix := f.enrollPhone(t, r)
	tok := f.mfaRequired(t)
	status, b := f.phoneChallenge(t, tok, "voice|"+suffix)
	if status != 200 || b["challenge_type"] != "oob" || b["binding_method"] != "prompt" || b["oob_code"] == "" {
		t.Fatalf("voice challenge = %d %v", status, b)
	}
	in := r.last(t)
	if in.Message.DeliveryMethod != "voice" || in.MessageType != "otp_verify" || in.Message.To != "+14155550100" {
		t.Fatalf("voice message = %+v %s", in.Message, in.MessageType)
	}
	form := mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", in.Message.Code)
	if w, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form}); w.Code != 200 {
		t.Fatalf("voice grant = %d %v", w.Code, body)
	}
	// A provider without voice (sns) refuses a voice challenge before sending.
	ctx := context.Background()
	if err := f.st.Phone().UpdatePhoneProvider(ctx, &store.PhoneProvider{TenantID: f.tenantID(t, "acme"), ID: "pro_1", Name: "sns", Configuration: json.RawMessage(`{"region":"us-east-1","delivery_methods":["text"]}`), SealedCredentials: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	tok = f.mfaRequired(t)
	sent := r.count()
	if status, b = f.phoneChallenge(t, tok, "voice|"+suffix); status != 400 || r.count() != sent {
		t.Fatalf("voice through sns = %d %v", status, b)
	}
}

func TestMFAOOBGrantSMS(t *testing.T) {
	f, r := mfaPhoneFixture(t)
	suffix := f.enrollPhone(t, r)
	tok := f.mfaRequired(t)
	status, b := f.phoneChallenge(t, tok, "sms|"+suffix)
	if status != 200 || b["oob_code"] == "" {
		t.Fatalf("sms challenge = %d %v", status, b)
	}
	in := r.last(t)
	if in.Message.DeliveryMethod != "text" || in.MessageType != "otp_verify" {
		t.Fatalf("sms message = %+v", in.Message)
	}
	rec := &eventRecorder{}
	f.h.Recorder = rec
	wrong := "000000"
	if in.Message.Code == wrong {
		wrong = "111111"
	}
	form := mfaForm(oobGrant, tok, "oob_code", b["oob_code"].(string))
	form.Set("binding_code", wrong)
	if w, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form}); w.Code != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong code = %d %v", w.Code, body)
	}
	failed := false
	for _, e := range rec.events {
		failed = failed || e.Type == "feoobft"
	}
	if !failed {
		t.Fatalf("missing feoobft: %v", rec.events)
	}
	form.Set("binding_code", in.Message.Code)
	if w, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form}); w.Code != 200 || body["access_token"] == nil {
		t.Fatalf("sms grant = %d %v", w.Code, body)
	}
	if w, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form}); w.Code == 200 {
		t.Fatalf("replayed grant = %d %v", w.Code, body)
	}
	// An authenticator_id-less oob challenge picks the phone method's
	// preferred delivery method.
	tok = f.mfaRequired(t)
	if status, b = f.phoneChallenge(t, tok, ""); status != 200 || r.last(t).Message.DeliveryMethod != "text" {
		t.Fatalf("default oob challenge = %d %v", status, b)
	}
}

func TestPhoneThrottleShared(t *testing.T) {
	f, r := mfaPhoneFixture(t)
	suffix := f.enrollPhone(t, r)
	ctx := context.Background()
	// Hosted pages call the same service: nine more sends spend the hourly
	// budget that the enrollment started.
	for i := 1; i < 10; i++ {
		if _, err := f.h.MFA.BeginPhoneChallenge(ctx, f.tenantID(t, "acme"), f.aliceID(t), "phone|"+suffix, "sms"); err != nil {
			t.Fatalf("send %d: %v", i+1, err)
		}
	}
	rec := &eventRecorder{}
	f.h.Recorder = rec
	f.h.MFA.Recorder = rec
	tok := f.mfaRequired(t)
	sent := r.count()
	status, b := f.phoneChallenge(t, tok, "sms|"+suffix)
	if status != 429 || b["error"] != "too_many_attempts" || r.count() != sent {
		t.Fatalf("exhausted challenge = %d %v", status, b)
	}
	limited := false
	for _, e := range rec.events {
		limited = limited || e.Type == "limit_phone"
	}
	if !limited {
		t.Fatalf("missing limit_phone: %v", rec.events)
	}
}
