package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const phoneCode = "731946"

func phoneInput(typ, method string) actions.PhoneInput {
	return actions.PhoneInput{Tenant: "t1", MessageType: typ, AsText: "Your code is " + phoneCode, AsVoice: "Your code is 7.3.1.9.4.6",
		Message: phone.Message{TenantID: "t1", To: "+14155550100", DeliveryMethod: method, Type: typ, Body: "Your code is " + phoneCode, From: "Acme", Code: phoneCode, Locale: "de", UserID: "auth0|u1", ClientID: "cli1"},
		Request: actions.RequestInfo{IP: "203.0.113.7", UserAgent: "UA/2", Language: "de"}}
}

// noCodeLeaks checks every execution record of trigger and the engine log.
func noCodeLeaks(t *testing.T, h *harness, trigger string) []store.Execution {
	t.Helper()
	exs, err := h.st.Actions().ListExecutions(context.Background(), "t1", store.ExecutionFilter{Trigger: trigger, Take: 100})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exs)
	if strings.Contains(string(raw), phoneCode) {
		t.Fatalf("code in execution records: %s", raw)
	}
	if strings.Contains(h.logs.String(), phoneCode) {
		t.Fatalf("code in slog output: %s", h.logs.String())
	}
	return exs
}

func TestCustomPhoneProviderEvent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.st.Clients().Create(ctx, &store.Client{TenantID: "t1", ClientID: "cli1", Name: "Portal"}); err != nil {
		t.Fatal(err)
	}
	if err := h.eng.RunPhoneProvider(ctx, phoneInput("otp_verify", "text")); !errors.Is(err, phone.ErrActionUnbound) {
		t.Fatalf("unbound: %v", err)
	}
	if ok, err := h.eng.PhoneActionBound(ctx, "t1", actions.TriggerCustomPhoneProvider); ok || err != nil {
		t.Fatalf("bound before binding: %v %v", ok, err)
	}
	check := `const n=e.notification;
if(n.message_type!=='otp_verify'||n.as_text!=='Your code is ` + phoneCode + `'||n.as_voice!=='Your code is 7.3.1.9.4.6'||n.delivery_method!=='text'||n.recipient!=='+14155550100'||n.from!=='Acme'||n.code!=='` + phoneCode + `'||n.locale!=='de')throw Error('bad notification '+JSON.stringify(Object.keys(n)));
if(e.user.user_id!=='auth0|u1'||e.client.client_id!=='cli1'||e.client.name!=='Portal'||e.tenant.id!=='t1'||e.request.ip!=='203.0.113.7'||e.request.user_agent!=='UA/2')throw Error('bad context');
console.log('sending '+n.code);console.error(n.code);`
	a := h.action("t1", actions.TriggerCustomPhoneProvider, "phone", `exports.onExecuteCustomPhoneProvider=async(e,a)=>{`+check+`}`, nil, false)
	h.bind("t1", a.Trigger, a)
	if ok, err := h.eng.PhoneActionBound(ctx, "t1", actions.TriggerCustomPhoneProvider); !ok || err != nil {
		t.Fatalf("bound: %v %v", ok, err)
	}
	if err := h.eng.RunPhoneProvider(ctx, phoneInput("otp_verify", "text")); err != nil {
		t.Fatal(err)
	}
	exs := noCodeLeaks(t, h, actions.TriggerCustomPhoneProvider)
	if len(exs) != 1 || len(exs[0].Results) != 1 || len(exs[0].Results[0].Logs) == 0 || exs[0].Results[0].ErrorID != "" {
		t.Fatalf("execution = %+v", exs)
	}

	// Drop: terminal delivery failure, the reason is masked.
	h.redeploy(a, `exports.onExecuteCustomPhoneProvider=async(e,a)=>{a.notification.drop('blocked '+e.notification.code)}`)
	err := h.eng.RunPhoneProvider(ctx, phoneInput("otp_verify", "text"))
	if phone.ClassOf(err) != phone.ClassTransient || strings.Contains(err.Error(), phoneCode) {
		t.Fatalf("drop: %v", err)
	}
	// Throw: delivery failure, not retried.
	h.redeploy(a, `exports.onExecuteCustomPhoneProvider=async(e)=>{throw Error('vendor down '+e.notification.code)}`)
	err = h.eng.RunPhoneProvider(ctx, phoneInput("otp_verify", "text"))
	if phone.ClassOf(err) != phone.ClassTransient || strings.Contains(err.Error(), phoneCode) {
		t.Fatalf("throw: %v", err)
	}
	if js, _ := h.st.Actions().ClaimJobs(ctx, h.clock().Add(time.Hour), time.Minute, 1); len(js) != 0 {
		t.Fatal("a thrown Action was queued for retry")
	}
	noCodeLeaks(t, h, actions.TriggerCustomPhoneProvider)

	// Retry: accepted now and retried by a durable job, up to five retries.
	h.redeploy(a, `exports.onExecuteCustomPhoneProvider=async(e,a)=>{if(e.notification.code!=='`+phoneCode+`')throw Error('lost code');a.notification.retry('later '+e.notification.code)}`)
	if err := h.eng.RunPhoneProvider(ctx, phoneInput("otp_verify", "text")); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if js, _ := h.st.Actions().ClaimJobs(ctx, h.clock(), time.Minute, 1); len(js) != 0 {
		t.Fatal("retry job due immediately")
	}
	attempts := 0
	for {
		h.advance(time.Hour)
		js, err := h.st.Actions().ClaimJobs(ctx, h.clock(), time.Minute, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(js) == 0 {
			break
		}
		raw, _ := json.Marshal(js[0])
		if strings.Contains(string(raw), phoneCode) {
			t.Fatal("retry envelope persisted the code in plaintext")
		}
		attempts++
		finishJob(t, h, &js[0])
		if attempts > 10 {
			t.Fatal("unbounded retries")
		}
	}
	if attempts != 5 {
		t.Fatalf("retries = %d, want 5", attempts)
	}
	noCodeLeaks(t, h, actions.TriggerCustomPhoneProvider)
}

func TestSendPhoneMessageEvent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.eng.RunSendPhoneMessage(ctx, phoneInput("otp_verify", "text")); !errors.Is(err, phone.ErrActionUnbound) {
		t.Fatalf("unbound: %v", err)
	}
	a := h.action("t1", actions.TriggerSendPhoneMessage, "hook", `exports.onExecuteSendPhoneMessage=async(e,a)=>{
const m=e.message_options;
if(m.recipient!=='+14155550100'||m.code!=='`+phoneCode+`'||m.text!==(m.message_type==='voice'?'Your code is 7.3.1.9.4.6':'Your code is `+phoneCode+`'))throw Error('bad message_options');
if(e.user.user_id!=='auth0|u1'||e.tenant.id!=='t1'||e.request.ip!=='203.0.113.7')throw Error('bad context');
console.log(m.action+' '+m.message_type+' '+m.code);}`, nil, false)
	h.bind("t1", a.Trigger, a)
	for _, c := range []struct{ typ, method, action, mt string }{
		{"otp_verify", "text", "second-factor-authentication", "sms"},
		{"otp_enroll", "text", "enrollment", "sms"},
		{"otp_verify", "voice", "second-factor-authentication", "voice"},
	} {
		in := phoneInput(c.typ, c.method)
		if c.method == "voice" {
			in.Message.Body = in.AsVoice
		}
		h.advance(time.Second)
		if err := h.eng.RunSendPhoneMessage(ctx, in); err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		exs := noCodeLeaks(t, h, actions.TriggerSendPhoneMessage)
		if got := strings.Join(exs[0].Results[0].Logs, "\n"); !strings.Contains(got, c.action+" "+c.mt+" ") {
			t.Fatalf("%+v: logs %q", c, got)
		}
	}
	h.redeploy(a, `exports.onExecuteSendPhoneMessage=async(e)=>{throw Error('hook failed '+e.message_options.code)}`)
	err := h.eng.RunSendPhoneMessage(ctx, phoneInput("otp_verify", "text"))
	if phone.ClassOf(err) != phone.ClassTransient || strings.Contains(err.Error(), phoneCode) {
		t.Fatalf("throw: %v", err)
	}
	noCodeLeaks(t, h, actions.TriggerSendPhoneMessage)
}
