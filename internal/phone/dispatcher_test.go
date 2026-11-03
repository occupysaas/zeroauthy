package phone

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const testCode = "482913"

// providerHit is one request seen by the fake Twilio/SNS/gateway server.
type providerHit struct {
	path string
	form url.Values
	json map[string]any
	auth string
}

type fakeProviders struct {
	mu     sync.Mutex
	hits   []providerHit
	status int32
}

func (f *fakeProviders) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	h := providerHit{path: r.URL.Path, auth: r.Header.Get("Authorization")}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.Unmarshal(raw, &h.json)
	} else {
		h.form, _ = url.ParseQuery(string(raw))
	}
	f.mu.Lock()
	f.hits = append(f.hits, h)
	f.mu.Unlock()
	status := int(atomic.LoadInt32(&f.status))
	if status == 0 {
		status = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if strings.Contains(r.URL.Path, "/sns/") {
		_, _ = io.WriteString(w, `<PublishResponse><PublishResult><MessageId>m1</MessageId></PublishResult></PublishResponse>`)
		return
	}
	_, _ = io.WriteString(w, `{"sid":"SM1"}`)
}

func (f *fakeProviders) last(t *testing.T) providerHit {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hits) == 0 {
		t.Fatal("no provider request")
	}
	h := f.hits[len(f.hits)-1]
	f.hits = nil
	return h
}

func (f *fakeProviders) none(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hits) != 0 {
		t.Fatalf("unexpected provider requests: %+v", f.hits)
	}
}

// fakeRunner stands in for the Actions engine.
type fakeRunner struct {
	mu    sync.Mutex
	bound map[string]bool
	calls []ActionInput
	err   error
}

func (f *fakeRunner) PhoneActionBound(_ context.Context, _ string, trigger string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bound[trigger], nil
}

func (f *fakeRunner) RunPhoneAction(_ context.Context, _ string, in ActionInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	return f.err
}

func (f *fakeRunner) take(t *testing.T) ActionInput {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 {
		t.Fatalf("action calls = %d", len(f.calls))
	}
	c := f.calls[0]
	f.calls = nil
	return c
}

type env struct {
	t      *testing.T
	ctx    context.Context
	st     *memory.Store
	w      keys.Wrapper
	fake   *fakeProviders
	runner *fakeRunner
	d      *Dispatcher
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t1", Name: "acme", FriendlyName: "Acme", SupportEmail: "help@acme.test", SettingsExtra: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(ctx, &store.User{TenantID: "t1", UserID: "sms|u1", Name: "Ada", PhoneNumber: "+14155550100",
		Identities: []store.Identity{{Connection: "sms", Provider: "sms", UserID: "u1"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Clients().Create(ctx, &store.Client{TenantID: "t1", ClientID: "cli1", Name: "Portal"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProviders{}
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	plain := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(plain.Close)
	useEndpoints(t, plain.URL, plain.URL+"/sns/")
	// The gateway client reaches the TLS fake whatever host the URL names.
	addr := srv.Listener.Addr().String()
	gw := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
	r := &fakeRunner{bound: map[string]bool{}}
	e := &env{t: t, ctx: ctx, st: st, w: w, fake: f, runner: r}
	e.d = &Dispatcher{Store: st, Wrapper: w, Actions: r, GatewayHTTP: gw}
	return e
}

func (e *env) consolidated(on bool) {
	e.t.Helper()
	tn, _ := e.st.Tenants().Get(e.ctx, "t1")
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["phone_consolidated_experience"] = on
	if err := e.st.Tenants().Update(e.ctx, tn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) provider(name, cfg string, creds map[string]string, disabled bool) {
	e.t.Helper()
	sealed := []byte(nil)
	if creds != nil {
		raw, _ := json.Marshal(creds)
		var err error
		if sealed, err = keys.SealBound(e.w, ProviderCredentialsLabel, ProviderCredentialsAAD("t1", name), raw); err != nil {
			e.t.Fatal(err)
		}
	}
	list, _ := e.st.Phone().ListPhoneProviders(e.ctx, "t1")
	p := &store.PhoneProvider{TenantID: "t1", ID: "pro_1", Name: name, Disabled: disabled, Configuration: json.RawMessage(cfg), SealedCredentials: sealed}
	var err error
	if len(list) > 0 {
		err = e.st.Phone().UpdatePhoneProvider(e.ctx, p)
	} else {
		err = e.st.Phone().CreatePhoneProvider(e.ctx, p)
	}
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) twilioBranding() {
	e.provider("twilio", `{"sid":"ACbrand","default_from":"+15550001111","delivery_methods":["text","voice"]}`, map[string]string{"auth_token": "brand-token"}, false)
}

func (e *env) template(typ, text, voice, from string) {
	e.t.Helper()
	c, _ := json.Marshal(map[string]any{"from": from, "syntax": "liquid", "body": map[string]any{"text": text, "voice": voice}})
	if err := e.st.Phone().PutPhoneTemplate(e.ctx, &store.PhoneTemplate{TenantID: "t1", ID: "tem_" + typ, Type: typ, Content: c, Customizable: true}); err != nil {
		e.t.Fatal(err)
	}
}

// guardian stores Plan 33 Guardian phone records.
func (e *env) guardian(selected string) {
	e.t.Helper()
	g, err := e.st.MFA().GetGuardian(e.ctx, "t1")
	if err != nil {
		e.t.Fatal(err)
	}
	if g.Stored == nil {
		g.Stored = map[string]json.RawMessage{}
	}
	if g.SealedSecrets == nil {
		g.SealedSecrets = map[string][]byte{}
	}
	g.Stored["/guardian/factors/phone/selected-provider"] = json.RawMessage(`{"provider":"` + selected + `"}`)
	g.Stored["/guardian/factors/phone/providers/twilio"] = json.RawMessage(`{"sid":"ACguard","from":"+15550009999"}`)
	g.Stored["/guardian/factors/phone/templates"] = json.RawMessage(`{"enrollment_message":"GE-{{code}}","verification_message":"G-{{code}} {{tenant.friendlyName}}"}`)
	sealed, err := keys.SealBound(e.w, "guardian-provider/v1", []string{"t1", "/guardian/factors/phone/providers/twilio"}, []byte(`{"auth_token":"guard-token"}`))
	if err != nil {
		e.t.Fatal(err)
	}
	g.SealedSecrets["/guardian/factors/phone/providers/twilio"] = sealed
	if err := e.st.MFA().PutGuardian(e.ctx, g, g.Version); err != nil {
		e.t.Fatal(err)
	}
}

var smsSID = "AC" + strings.Repeat("c", 32)

// smsConnection stores an sms connection built through connrules.
func (e *env) smsConnection(opts string, secrets map[string]string) string {
	e.t.Helper()
	var s connrules.Spec
	if err := json.Unmarshal([]byte(`{"name":"sms","strategy":"sms","options":`+opts+`}`), &s); err != nil {
		e.t.Fatal(err)
	}
	connrules.CreateDefaults(&s)
	if errs := connrules.NormalizeAPI(&s); len(errs) > 0 {
		e.t.Fatal(errs)
	}
	c := &store.Connection{TenantID: "t1", ID: "con_sms"}
	connrules.Apply(&s, c)
	sealed, err := keys.SealConnectionConfig(e.w, "t1", c.ID, secrets)
	if err != nil {
		e.t.Fatal(err)
	}
	c.ConfigurationSealed = sealed
	op := e.st.Connections().Create
	if _, err := e.st.Connections().Get(e.ctx, "t1", c.ID); err == nil {
		op = e.st.Connections().Update
	}
	if err := op(e.ctx, c); err != nil {
		e.t.Fatal(err)
	}
	return c.ID
}

func msg(typ, method string) Message {
	return Message{To: "+14155550100", DeliveryMethod: method, Type: typ, Code: testCode, Locale: "en", UserID: "sms|u1", ClientID: "cli1"}
}

func messageTypeFor(purpose string) string {
	switch purpose {
	case "passwordless":
		return "passwordless"
	case "reset":
		return "change_password"
	}
	return "otp_verify"
}

func TestDispatcherRouting(t *testing.T) {
	for _, rule := range phonerules.Routing() {
		name := rule.Purpose + "/" + map[bool]string{true: "consolidated", false: "legacy"}[rule.Consolidated] + "/" + rule.GuardianProvider + rule.ConnectionProvider
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.consolidated(rule.Consolidated)
			e.twilioBranding()
			e.template("otp_verify", "B-{{ code }}", "BV-{{ code }}", "")
			e.template("otp_enroll", "BE-{{ code }}", "BEV-{{ code }}", "")
			e.template("change_password", "BR-{{ code }}", "BRV-{{ code }}", "")
			e.guardian(map[string]string{"": "auth0"}[rule.GuardianProvider] + rule.GuardianProvider)
			e.runner.bound[TriggerSendPhoneMessage] = true
			route := Route{Purpose: rule.Purpose}
			if rule.Purpose == "passwordless" {
				route.ConnectionID = e.smsConnection(`{"provider":"`+rule.ConnectionProvider+`","from":"+15550002222","twilio_sid":"`+smsSID+`","gateway_url":"https://gateway.example.test/sms","template":"C-@@password@@"}`,
					map[string]string{connrules.SecretTwilioToken: strings.Repeat("t", 32)})
			}
			if ok, err := e.d.Working(e.ctx, "t1", route); err != nil || !ok {
				t.Fatalf("working = %v, %v", ok, err)
			}
			if _, err := e.d.Send(e.ctx, "t1", route, msg(messageTypeFor(rule.Purpose), "text")); err != nil {
				t.Fatal(err)
			}
			wantBody := map[string]string{"branding:otp_enroll|otp_verify": "B-" + testCode, "guardian:enrollment_message|verification_message": "G-" + testCode + " Acme",
				"branding:otp_verify": "B-" + testCode, "branding:change_password": "BR-" + testCode, "connection:template": "C-" + testCode}[rule.Template]
			switch rule.Sender {
			case "branding":
				h := e.fake.last(t)
				if h.path != "/2010-04-01/Accounts/ACbrand/Messages.json" || h.form.Get("Body") != wantBody || h.form.Get("From") != "+15550001111" {
					t.Fatalf("branding hit = %+v", h)
				}
			case "guardian-twilio":
				h := e.fake.last(t)
				if h.path != "/2010-04-01/Accounts/ACguard/Messages.json" || h.form.Get("Body") != wantBody || h.form.Get("From") != "+15550009999" {
					t.Fatalf("guardian hit = %+v", h)
				}
			case "action:send-phone-message":
				in := e.runner.take(t)
				if in.Trigger != TriggerSendPhoneMessage || in.Message.Body != wantBody || in.Message.Code != testCode || in.MessageType != "otp_verify" {
					t.Fatalf("action input = %+v", in)
				}
				e.fake.none(t)
			case "connection-twilio":
				h := e.fake.last(t)
				if h.path != "/2010-04-01/Accounts/"+smsSID+"/Messages.json" || h.form.Get("Body") != wantBody || h.form.Get("From") != "+15550002222" {
					t.Fatalf("connection twilio hit = %+v", h)
				}
			case "connection-gateway":
				h := e.fake.last(t)
				if h.path != "/sms" || h.json["body"] != wantBody || h.json["recipient"] != "+14155550100" || h.json["sender"] != "+15550002222" {
					t.Fatalf("gateway hit = %+v", h)
				}
			default:
				t.Fatalf("untested sender %q", rule.Sender)
			}
		})
	}
}

func TestDispatcherGuardianAuth0UsesBranding(t *testing.T) {
	e := newEnv(t)
	e.consolidated(false)
	e.guardian("auth0")
	e.twilioBranding()
	route := Route{Purpose: "mfa"}
	if _, err := e.d.Send(e.ctx, "t1", route, msg("otp_enroll", "text")); err != nil {
		t.Fatal(err)
	}
	h := e.fake.last(t)
	if h.path != "/2010-04-01/Accounts/ACbrand/Messages.json" || h.form.Get("Body") != "GE-"+testCode {
		t.Fatalf("auth0 must send through the branding provider with the Guardian template: %+v", h)
	}
	// Voice reads the code digit by digit.
	if _, err := e.d.Send(e.ctx, "t1", route, msg("otp_verify", "voice")); err != nil {
		t.Fatal(err)
	}
	h = e.fake.last(t)
	if h.path != "/2010-04-01/Accounts/ACbrand/Calls.json" || !strings.Contains(h.form.Get("Twiml"), "G-4.8.2.9.1.3") {
		t.Fatalf("voice = %+v", h)
	}
}

func TestDispatcherGuardianAuth0FailsClosedWithoutProvider(t *testing.T) {
	e := newEnv(t)
	e.consolidated(false)
	e.guardian("auth0")
	route := Route{Purpose: "mfa"}
	if ok, err := e.d.Working(e.ctx, "t1", route); err != nil || ok {
		t.Fatalf("working without a branding provider = %v, %v", ok, err)
	}
	_, err := e.d.Send(e.ctx, "t1", route, msg("otp_verify", "text"))
	if !errors.Is(err, ErrNoProvider) || ClassOf(err) == "" {
		t.Fatalf("send = %v", err)
	}
	e.fake.none(t)
	if FailureCode("mfa", "text") != "gd_send_sms_failure" || FailureCode("mfa", "voice") != "gd_send_voice_failure" || FailureCode("passwordless", "text") != "fn" {
		t.Fatal("failure log codes")
	}
}

func TestDispatcherWorkingDefinition(t *testing.T) {
	e := newEnv(t)
	e.consolidated(true)
	route := Route{Purpose: "verify"}
	cases := []struct {
		name  string
		setup func()
		want  bool
	}{
		{"no provider", func() {}, false},
		{"twilio configured", e.twilioBranding, true},
		{"twilio disabled", func() {
			e.provider("twilio", `{"sid":"ACbrand","delivery_methods":["text"]}`, map[string]string{"auth_token": "x"}, true)
		}, false},
		{"twilio without credentials", func() { e.provider("twilio", `{"sid":"ACbrand","delivery_methods":["text"]}`, nil, false) }, false},
		{"sns configured", func() {
			e.provider("sns", `{"region":"us-east-1","delivery_methods":["text"]}`, map[string]string{"access_key_id": "a", "secret_access_key": "s"}, false)
		}, true},
		{"sns without region", func() {
			e.provider("sns", `{"delivery_methods":["text"]}`, map[string]string{"access_key_id": "a", "secret_access_key": "s"}, false)
		}, false},
		{"custom without bound Action", func() { e.provider("custom", `{"delivery_methods":["text","voice"]}`, nil, false) }, false},
		{"custom with bound Action", func() { e.runner.bound[TriggerCustomPhoneProvider] = true }, true},
		{"custom disabled", func() { e.provider("custom", `{"delivery_methods":["text"]}`, nil, true) }, false},
	}
	for _, c := range cases {
		c.setup()
		if ok, err := e.d.Working(e.ctx, "t1", route); err != nil || ok != c.want {
			t.Fatalf("%s: working = %v, %v", c.name, ok, err)
		}
	}
	// Bound custom provider: both bodies reach the Action; the runner being
	// down at send time is a transient delivery failure.
	e.provider("custom", `{"delivery_methods":["text","voice"]}`, nil, false)
	if _, err := e.d.Send(e.ctx, "t1", route, msg("otp_verify", "text")); err != nil {
		t.Fatal(err)
	}
	in := e.runner.take(t)
	if in.Trigger != TriggerCustomPhoneProvider || in.MessageType != "otp_verify" || in.Message.Code != testCode ||
		!strings.Contains(in.AsText, testCode) || !strings.Contains(in.AsVoice, "4.8.2.9.1.3") || in.Message.To != "+14155550100" {
		t.Fatalf("custom input = %+v", in)
	}
	e.runner.err = &SendError{Class: ClassTransient, Err: errors.New("runner unavailable")}
	if _, err := e.d.Send(e.ctx, "t1", route, msg("otp_verify", "text")); ClassOf(err) != ClassTransient {
		t.Fatalf("runner down: %v", err)
	}
	if ok, _ := e.d.Working(e.ctx, "t1", route); !ok {
		t.Fatal("a send-time failure must not change what is offered")
	}
}

// Review Focus 5: switching providers keeps outstanding codes; new sends use
// the new provider; with none, sends fail closed.
func TestProviderSwitchKeepsCodes(t *testing.T) {
	e := newEnv(t)
	e.consolidated(true)
	conn := e.smsConnection(`{"provider":"twilio","twilio_sid":"`+smsSID+`"}`, map[string]string{connrules.SecretTwilioToken: strings.Repeat("t", 32)})
	route := Route{Purpose: "passwordless", ConnectionID: conn}
	now := time.Now()
	code := &store.PasswordlessCode{TenantID: "t1", ConnectionID: conn, Identifier: "+14155550100", ClientID: "cli1", Kind: "code", CodeHash: "h1", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := e.st.Phone().PutPasswordlessCode(e.ctx, code); err != nil {
		t.Fatal(err)
	}
	e.twilioBranding()
	if _, err := e.d.Send(e.ctx, "t1", route, msg("passwordless", "text")); err != nil {
		t.Fatal(err)
	}
	if h := e.fake.last(t); !strings.Contains(h.path, "ACbrand") {
		t.Fatalf("twilio: %+v", h)
	}
	e.provider("sns", `{"region":"us-east-1","delivery_methods":["text"]}`, map[string]string{"access_key_id": "a", "secret_access_key": "s"}, false)
	if _, err := e.d.Send(e.ctx, "t1", route, msg("passwordless", "text")); err != nil {
		t.Fatal(err)
	}
	if h := e.fake.last(t); h.path != "/sns/" || h.form.Get("Message") == "" {
		t.Fatalf("sns: %+v", h)
	}
	e.provider("custom", `{"delivery_methods":["text"]}`, nil, false)
	e.runner.bound[TriggerCustomPhoneProvider] = true
	if _, err := e.d.Send(e.ctx, "t1", route, msg("passwordless", "text")); err != nil {
		t.Fatal(err)
	}
	if in := e.runner.take(t); in.Trigger != TriggerCustomPhoneProvider {
		t.Fatalf("custom: %+v", in)
	}
	if err := e.st.Phone().DeletePhoneProvider(e.ctx, "t1", "pro_1"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.d.Working(e.ctx, "t1", route); ok {
		t.Fatal("deleted provider still works")
	}
	if _, err := e.d.Send(e.ctx, "t1", route, msg("passwordless", "text")); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("send without provider: %v", err)
	}
	got, err := e.st.Phone().ConsumePasswordlessCode(e.ctx, "t1", conn, "+14155550100", "code", "h1", 3, time.Now())
	if err != nil || got == nil {
		t.Fatalf("outstanding code lost across provider switches: %v", err)
	}
}

func TestTemplateRenderVariables(t *testing.T) {
	e := newEnv(t)
	e.consolidated(true)
	e.twilioBranding()
	e.template("otp_verify", "{{ code }}|{{ friendly_name }}|{{ tenant }}|{{ user.name }}|{{ client.name }}|{{ application.name }}|{{ locale }}|{{ support_email }}|{{ connection }}",
		"{{ code }}", "Acme")
	conn := e.smsConnection(`{"provider":"twilio","twilio_sid":"`+smsSID+`"}`, map[string]string{connrules.SecretTwilioToken: strings.Repeat("t", 32)})
	if _, err := e.d.Send(e.ctx, "t1", Route{Purpose: "verify", ConnectionID: conn}, msg("otp_verify", "text")); err != nil {
		t.Fatal(err)
	}
	h := e.fake.last(t)
	if want := testCode + "|Acme|acme|Ada|Portal|Portal|en|help@acme.test|sms"; h.form.Get("Body") != want {
		t.Fatalf("branding body = %q, want %q", h.form.Get("Body"), want)
	}
	if h.form.Get("From") != "Acme" {
		t.Fatalf("template from must reach Twilio: %q", h.form.Get("From"))
	}
	// SNS takes From as an alphanumeric sender ID: a phone number is not one.
	e.provider("sns", `{"region":"us-east-1","sender_id":"Default","delivery_methods":["text"]}`, map[string]string{"access_key_id": "a", "secret_access_key": "s"}, false)
	for from, want := range map[string]string{"Acme": "Acme", "+15550001111": "Default"} {
		e.template("otp_verify", "{{ code }}", "{{ code }}", from)
		if _, err := e.d.Send(e.ctx, "t1", Route{Purpose: "verify"}, msg("otp_verify", "text")); err != nil {
			t.Fatal(err)
		}
		if got := e.fake.last(t).form.Get("MessageAttributes.entry.1.Value.StringValue"); got != want {
			t.Fatalf("sns sender id for from %q = %q, want %q", from, got, want)
		}
	}
	// Legacy SMS connection template: md_with_macros and liquid syntaxes.
	e.consolidated(false)
	for syntax, tpl := range map[string]string{"md_with_macros": "@@password@@ @@code@@ @@phone_number@@ @@application.name@@ @@request_language@@", "liquid": "{{ password }} {{ code }} {{ phone_number }} {{ application.name }} {{ request_language }}"} {
		conn = e.smsConnection(`{"provider":"twilio","from":"+15550002222","twilio_sid":"`+smsSID+`","syntax":"`+syntax+`","template":"`+tpl+`"}`, map[string]string{connrules.SecretTwilioToken: strings.Repeat("t", 32)})
		ctx := WithRequest(e.ctx, Request{Language: "fr"})
		if _, err := e.d.Send(ctx, "t1", Route{Purpose: "passwordless", ConnectionID: conn}, msg("passwordless", "text")); err != nil {
			t.Fatal(err)
		}
		if got, want := e.fake.last(t).form.Get("Body"), testCode+" "+testCode+" +14155550100 Portal fr"; got != want {
			t.Fatalf("%s body = %q, want %q", syntax, got, want)
		}
	}
	// A disabled branding template sends nothing.
	e.consolidated(true)
	if err := e.st.Phone().PutPhoneTemplate(e.ctx, &store.PhoneTemplate{TenantID: "t1", ID: "tem_otp_verify", Type: "otp_verify", Disabled: true, Content: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.Send(e.ctx, "t1", Route{Purpose: "verify"}, msg("otp_verify", "text")); !errors.Is(err, ErrTemplateDisabled) {
		t.Fatalf("disabled template: %v", err)
	}
	e.fake.none(t)
}

func TestSMSGatewayJWTAndSSRF(t *testing.T) {
	e := newEnv(t)
	e.consolidated(false)
	secret := "gateway-signing-secret"
	conn := e.smsConnection(`{"provider":"sms_gateway","from":"Acme","gateway_url":"https://gateway.example.test/sms","forward_req_info":true,"template":"code @@code@@","gateway_authentication":{"audience":"urn:gw","method":"bearer","subject":"zeroauthy","secret":"`+secret+`"}}`,
		map[string]string{connrules.SecretGatewaySecret: secret})
	route := Route{Purpose: "passwordless", ConnectionID: conn}
	ctx := WithRequest(e.ctx, Request{IP: "203.0.113.9", UserAgent: "UA/1"})
	fixed := time.Unix(1_800_000_000, 0)
	e.d.Now = func() time.Time { return fixed }
	if _, err := e.d.Send(ctx, "t1", route, msg("passwordless", "text")); err != nil {
		t.Fatal(err)
	}
	h := e.fake.last(t)
	req, _ := h.json["req"].(map[string]any)
	if h.json["recipient"] != "+14155550100" || h.json["body"] != "code "+testCode || h.json["sender"] != "Acme" || req["ip"] != "203.0.113.9" || req["user-agent"] != "UA/1" {
		t.Fatalf("gateway body = %+v", h.json)
	}
	token, ok := strings.CutPrefix(h.auth, "Bearer ")
	parts := strings.Split(token, ".")
	if !ok || len(parts) != 3 {
		t.Fatalf("authorization = %q", h.auth)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Fatal("gateway JWT not signed with the gateway secret")
	}
	var header, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &header)
	_ = json.Unmarshal(cb, &claims)
	iat := float64(fixed.Unix())
	if header["alg"] != "HS256" || claims["sub"] != "zeroauthy" || claims["aud"] != "urn:gw" || claims["iat"] != iat || claims["exp"] != iat+float64(phonerules.Limits.GatewayJWTSeconds) {
		t.Fatalf("jwt header=%v claims=%v", header, claims)
	}
	// forward_req_info off: no req member.
	conn = e.smsConnection(`{"provider":"sms_gateway","gateway_url":"https://gateway.example.test/sms","template":"x @@code@@"}`, nil)
	if _, err := e.d.Send(ctx, "t1", route, msg("passwordless", "text")); err != nil {
		t.Fatal(err)
	}
	if h := e.fake.last(t); h.json["req"] != nil || h.auth != "" {
		t.Fatalf("unforwarded gateway request = %+v", h)
	}
	// Documented gateway failures.
	for status, want := range map[int32]string{401: "Authentication failed while calling the SMS gateway: 401", 500: "Unexpected response while calling the SMS gateway: 500", 404: "Unexpected response while calling the SMS gateway: 404"} {
		atomic.StoreInt32(&e.fake.status, status)
		_, err := e.d.Send(ctx, "t1", route, msg("passwordless", "text"))
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), testCode) {
			t.Fatalf("status %d: %v", status, err)
		}
		if status == 401 && ClassOf(err) != ClassProviderAuth {
			t.Fatalf("401 class = %s", ClassOf(err))
		}
		e.fake.last(t)
	}
	// Dial-time SSRF guard: CGNAT, numeric hosts and loopback are refused
	// without connecting (the write-time URL check cannot see resolution).
	client := NewGatewayClient(false)
	for _, target := range []string{"https://100.64.0.1/sms", "https://2130706433/sms", "https://127.0.0.1/sms", "https://[::1]/sms"} {
		g := NewGateway(GatewayConfig{URL: target}, client, nil)
		cctx, cancel := context.WithTimeout(e.ctx, 3*time.Second)
		_, err := g.Send(cctx, msg("passwordless", "text"))
		cancel()
		if err == nil || !strings.Contains(err.Error(), "address not allowed") && !strings.Contains(err.Error(), "request failed") {
			t.Fatalf("%s: %v", target, err)
		}
		if strings.Contains(target, "100.64") || strings.Contains(target, "127.0.0.1") || strings.Contains(target, "::1") {
			if !strings.Contains(err.Error(), "address not allowed") {
				t.Fatalf("%s not refused by the dial guard: %v", target, err)
			}
		}
	}
	var blocked error = httpx.ErrBlockedAddress
	if _, err := client.Get("https://100.64.0.1/"); !errors.Is(err, blocked) {
		t.Fatalf("cgnat dial: %v", err)
	}
	// Missing Twilio credentials on a connection fail the send.
	conn = e.smsConnection(`{"provider":"twilio","twilio_sid":"`+smsSID+`"}`, nil)
	if ok, _ := e.d.Working(e.ctx, "t1", route); ok {
		t.Fatal("twilio connection without a token works")
	}
	if _, err := e.d.Send(ctx, "t1", route, msg("passwordless", "text")); ClassOf(err) != ClassProviderAuth {
		t.Fatalf("missing twilio token: %v", err)
	}
	e.fake.none(t)
}
