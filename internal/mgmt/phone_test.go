package mgmt_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/phone"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

const phoneSecret = "SENTINEL_TWILIO_AUTH_TOKEN"

var allPhoneScopes = []string{"read:phone_providers", "create:phone_providers", "update:phone_providers", "delete:phone_providers", "read:phone_templates", "create:phone_templates", "update:phone_templates", "delete:phone_templates", "read:attack_protection", "update:attack_protection"}

type twilioFake struct {
	mu    sync.Mutex
	forms []url.Values
	paths []string
	auth  []string
}

func (f *twilioFake) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.forms) }

func newPhoneEnv(t *testing.T) (*clientsEnv, *twilioFake) {
	t.Helper()
	e := newClientsEnv(t)
	f := &twilioFake{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		f.mu.Lock()
		f.forms = append(f.forms, form)
		f.paths = append(f.paths, r.URL.Path)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"sid":"SM1"}`)
	}))
	t.Cleanup(srv.Close)
	old := phone.Endpoints
	phone.SetTestEndpoints(srv.URL, "")
	t.Cleanup(func() { phone.Endpoints = old })
	return e, f
}

func (e *clientsEnv) phone(t *testing.T, method, target string, body any, scopes []string, fn http.HandlerFunc) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec, out := e.call(t, e.tn, m2mCaller(scopes...), method, target, body, fn)
	m, _ := out.(map[string]any)
	return rec, m
}

func twilioBody() map[string]any {
	return map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": phoneSecret}, "configuration": map[string]any{"sid": "AC123", "default_from": "+15550001111", "delivery_methods": []string{"text", "voice"}}}
}

func (e *clientsEnv) createProvider(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	rec, out := e.phone(t, "POST", "/api/v2/branding/phone/providers", body, allPhoneScopes, e.h.CreatePhoneProvider)
	if rec.Code != 201 {
		t.Fatalf("create provider: %d %s", rec.Code, rec.Body)
	}
	return out
}

func (e *clientsEnv) tryProvider(t *testing.T, id string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := e.phone(t, "POST", "/api/v2/branding/phone/providers/"+id+"/try", body, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.TryPhoneProvider(w, r, id) })
	return rec
}

func TestPhoneProviderCRUD(t *testing.T) {
	e, _ := newPhoneEnv(t)
	created := e.createProvider(t, twilioBody())
	id, _ := created["id"].(string)
	if id == "" || created["name"] != "twilio" || created["channel"] != "phone" || created["disabled"] != false {
		t.Fatalf("created: %v", created)
	}
	if _, ok := created["credentials"]; ok {
		t.Fatalf("credentials returned: %v", created)
	}
	rec, _ := e.phone(t, "POST", "/api/v2/branding/phone/providers", twilioBody(), allPhoneScopes, e.h.CreatePhoneProvider)
	if rec.Code != 409 {
		t.Fatalf("second create: %d %s", rec.Code, rec.Body)
	}
	rec, got := e.phone(t, "GET", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.GetPhoneProvider(w, r, id) })
	if rec.Code != 200 || got["id"] != id || strings.Contains(rec.Body.String(), phoneSecret) || strings.Contains(rec.Body.String(), "credentials") {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	cfg, _ := got["configuration"].(map[string]any)
	if cfg["sid"] != "AC123" || cfg["default_from"] != "+15550001111" {
		t.Fatalf("configuration: %v", cfg)
	}
	list := func(q string, disabled *bool) []any {
		rec, out := e.phone(t, "GET", "/x"+q, nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) {
			e.h.ListPhoneProviders(w, r, mgmtapi.ListPhoneProvidersParams{Disabled: disabled})
		})
		if rec.Code != 200 {
			t.Fatalf("list: %d %s", rec.Code, rec.Body)
		}
		l, _ := out["providers"].([]any)
		return l
	}
	yes, no := true, false
	if len(list("", nil)) != 1 || len(list("", &no)) != 1 || len(list("", &yes)) != 0 {
		t.Fatal("list/disabled filter")
	}
	// PATCH keeps the sealed token when credentials are omitted and replaces it when given.
	rec, upd := e.phone(t, "PATCH", "/x", map[string]any{"disabled": true}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.UpdatePhoneProvider(w, r, id) })
	if rec.Code != 200 || upd["disabled"] != true {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	unseal := func() string {
		p, err := e.st.Phone().GetPhoneProvider(t.Context(), e.tn.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := keys.OpenBound(e.w, "phone-provider/v1", []string{e.tn.ID, p.Name}, p.SealedCredentials)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(p.Configuration), phoneSecret) {
			t.Fatal("secret in public configuration")
		}
		return string(plain)
	}
	if !strings.Contains(unseal(), phoneSecret) {
		t.Fatal("token not preserved")
	}
	rec, _ = e.phone(t, "PATCH", "/x", map[string]any{"credentials": map[string]any{"auth_token": "NEWTOKEN"}}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.UpdatePhoneProvider(w, r, id) })
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "NEWTOKEN") || !strings.Contains(unseal(), "NEWTOKEN") {
		t.Fatalf("replace token: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.phone(t, "DELETE", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.DeletePhoneProvider(w, r, id) })
	if rec.Code != 204 {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec, _ = e.phone(t, "GET", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.GetPhoneProvider(w, r, id) })
	if rec.Code != 404 {
		t.Fatalf("get after delete: %d", rec.Code)
	}
}

func TestPhoneProviderValidation(t *testing.T) {
	e, _ := newPhoneEnv(t)
	post := func(body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
		return e.phone(t, "POST", "/x", body, allPhoneScopes, e.h.CreatePhoneProvider)
	}
	bad := func(label string, body map[string]any) {
		t.Helper()
		if rec, _ := post(body); rec.Code != 400 {
			t.Fatalf("%s: %d %s", label, rec.Code, rec.Body)
		}
	}
	cfg := func(m map[string]any) map[string]any { return m }
	bad("unknown name", map[string]any{"name": "vonage", "credentials": map[string]any{}, "configuration": cfg(map[string]any{"delivery_methods": []string{"text"}})})
	bad("no credentials", map[string]any{"name": "twilio", "configuration": cfg(map[string]any{"sid": "AC1", "default_from": "+1555", "delivery_methods": []string{"text"}})})
	bad("twilio no sid", map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": "x"}, "configuration": cfg(map[string]any{"default_from": "+15550001111", "delivery_methods": []string{"text"}})})
	bad("twilio no from or mssid", map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": "x"}, "configuration": cfg(map[string]any{"sid": "AC1", "delivery_methods": []string{"text"}})})
	bad("twilio no token", map[string]any{"name": "twilio", "credentials": map[string]any{}, "configuration": cfg(map[string]any{"sid": "AC1", "mssid": "MG1", "delivery_methods": []string{"text"}})})
	bad("twilio voice needs from", map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": "x"}, "configuration": cfg(map[string]any{"sid": "AC1", "mssid": "MG1", "delivery_methods": []string{"voice"}})})
	bad("twilio region field", map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": "x"}, "configuration": cfg(map[string]any{"sid": "AC1", "mssid": "MG1", "region": "us-east-1", "delivery_methods": []string{"text"}})})
	bad("empty delivery methods", map[string]any{"name": "twilio", "credentials": map[string]any{"auth_token": "x"}, "configuration": cfg(map[string]any{"sid": "AC1", "mssid": "MG1", "delivery_methods": []string{}})})
	bad("sns voice", map[string]any{"name": "sns", "credentials": map[string]any{"access_key_id": "AK", "secret_access_key": "SK"}, "configuration": cfg(map[string]any{"region": "us-east-1", "delivery_methods": []string{"text", "voice"}})})
	bad("sns no region", map[string]any{"name": "sns", "credentials": map[string]any{"access_key_id": "AK", "secret_access_key": "SK"}, "configuration": cfg(map[string]any{"delivery_methods": []string{"text"}})})
	bad("sns no secret", map[string]any{"name": "sns", "credentials": map[string]any{"access_key_id": "AK"}, "configuration": cfg(map[string]any{"region": "us-east-1", "delivery_methods": []string{"text"}})})
	bad("sns bad sms_type", map[string]any{"name": "sns", "credentials": map[string]any{"access_key_id": "AK", "secret_access_key": "SK"}, "configuration": cfg(map[string]any{"region": "us-east-1", "sms_type": "Other", "delivery_methods": []string{"text"}})})
	rec, out := post(map[string]any{"name": "custom", "credentials": map[string]any{}, "configuration": cfg(map[string]any{"delivery_methods": []string{"text"}})})
	if rec.Code != 400 || out["errorCode"] != "custom_email_provider_deployed_action_not_found" {
		t.Fatalf("custom without action: %d %s", rec.Code, rec.Body)
	}
	rec, out = post(map[string]any{"name": "sns", "credentials": map[string]any{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "SENTINEL_SNS_SECRET"}, "configuration": cfg(map[string]any{"region": "us-east-1", "sender_id": "ZA", "sms_type": "Transactional", "delivery_methods": []string{"text"}})})
	if rec.Code != 201 || out["name"] != "sns" || strings.Contains(rec.Body.String(), "SENTINEL_SNS_SECRET") || strings.Contains(rec.Body.String(), "AKIAEXAMPLE") {
		t.Fatalf("sns create: %d %s", rec.Code, rec.Body)
	}
	// Custom is accepted once a custom-phone-provider Action is bound.
	id, _ := out["id"].(string)
	if rec, _ = e.phone(t, "DELETE", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.DeletePhoneProvider(w, r, id) }); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	bindCustomPhoneAction(t, e)
	rec, out = post(map[string]any{"name": "custom", "credentials": map[string]any{}, "configuration": cfg(map[string]any{"delivery_methods": []string{"text"}})})
	if rec.Code != 201 || out["name"] != "custom" {
		t.Fatalf("custom with action: %d %s", rec.Code, rec.Body)
	}
}

func bindCustomPhoneAction(t *testing.T, e *clientsEnv) {
	t.Helper()
	ae := actionstest.NewOffline(t, e.st, e.w)
	a := ae.Deploy(t, e.tn.ID, "custom-phone-provider", "phone", "exports.onExecuteCustomPhoneProvider = async () => {};")
	if _, err := e.st.Actions().ReplaceBindings(t.Context(), e.tn.ID, "custom-phone-provider", []store.Binding{{ActionID: a.ID, DisplayName: "phone"}}); err != nil {
		t.Fatal(err)
	}
}

func TestPhoneProviderTry(t *testing.T) {
	e, f := newPhoneEnv(t)
	id := e.createProvider(t, twilioBody())["id"].(string)
	rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100", "delivery_method": "text"})
	if rec.Code != 202 {
		t.Fatalf("try: %d %s", rec.Code, rec.Body)
	}
	if f.count() != 1 || f.forms[0].Get("To") != "+14155550100" || f.forms[0].Get("From") != "+15550001111" || f.forms[0].Get("Body") == "" || !strings.HasSuffix(f.paths[0], "/Messages.json") {
		t.Fatalf("fake saw %v %v", f.forms, f.paths)
	}
	if rec := e.tryProvider(t, id, map[string]any{"to": "not-a-number"}); rec.Code != 400 {
		t.Fatalf("bad number: %d", rec.Code)
	}
	if rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100", "delivery_method": "fax"}); rec.Code != 400 {
		t.Fatalf("bad method: %d", rec.Code)
	}
	if rec := e.tryProvider(t, "pro_missing", map[string]any{"to": "+14155550100"}); rec.Code != 404 {
		t.Fatalf("missing provider: %d", rec.Code)
	}
	// Voice: one new request per hour per number, then the budget refuses.
	if rec := e.tryProvider(t, id, map[string]any{"to": "+14155550101", "delivery_method": "voice"}); rec.Code != 202 {
		t.Fatalf("voice: %d %s", rec.Code, rec.Body)
	}
	before := f.count()
	rec = e.tryProvider(t, id, map[string]any{"to": "+14155550101", "delivery_method": "voice"})
	if rec.Code != 429 || f.count() != before {
		t.Fatalf("second voice: %d sent=%d", rec.Code, f.count()-before)
	}
	// Texts: 10 per number per hour in total (one already used above).
	n := 0
	for i := 0; i < 20; i++ {
		rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100"})
		if rec.Code == 429 {
			break
		}
		if rec.Code != 202 {
			t.Fatalf("try %d: %d", i, rec.Code)
		}
		n++
	}
	if n != 9 {
		t.Fatalf("texts before exhaustion after the first: %d", n)
	}
}

func TestPhoneProviderTryLimitLogsAndHidesNumber(t *testing.T) {
	e, _ := newPhoneEnv(t)
	c := logSetup(e)
	id := e.createProvider(t, twilioBody())["id"].(string)
	c.events = nil
	for i := 0; i < 2; i++ {
		e.tryProvider(t, id, map[string]any{"to": "+14155550102", "delivery_method": "voice"})
	}
	var limit, all string
	for _, ev := range c.events {
		all += eventJSON(t, ev)
		if ev.Type == "limit_phone" {
			limit = eventJSON(t, ev)
		}
	}
	if limit == "" {
		t.Fatalf("no limit_phone event: %s", all)
	}
	if strings.Contains(all, "4155550102") || strings.Contains(all, phoneSecret) {
		t.Fatalf("number or secret in events: %s", all)
	}
}

func TestPhoneProviderTryCustomAndSecretsInLogs(t *testing.T) {
	e, _ := newPhoneEnv(t)
	var buf strings.Builder
	e.h.Log = slog.New(slog.NewTextHandler(&buf, nil))
	c := &managementEvents{}
	e.h.Recorder = c
	bindCustomPhoneAction(t, e)
	id := e.createProvider(t, map[string]any{"name": "custom", "credentials": map[string]any{}, "configuration": map[string]any{"delivery_methods": []string{"text"}}})["id"].(string)
	rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100"})
	if rec.Code != 409 {
		t.Fatalf("custom try: %d %s", rec.Code, rec.Body)
	}
	e.h.Store.Phone().DeletePhoneProvider(t.Context(), e.tn.ID, id)
	e.createProvider(t, twilioBody())
	var all string
	for _, ev := range c.events {
		all += eventJSON(t, ev)
	}
	if strings.Contains(all+buf.String(), phoneSecret) || strings.Contains(all+buf.String(), "4155550100") {
		t.Fatalf("secret or number logged: %s %s", all, buf.String())
	}
}

func TestPhoneTemplatesDefaultsAndReset(t *testing.T) {
	e, _ := newPhoneEnv(t)
	list := func() []any {
		rec, out := e.phone(t, "GET", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) {
			e.h.ListPhoneTemplates(w, r, mgmtapi.ListPhoneTemplatesParams{})
		})
		if rec.Code != 200 {
			t.Fatalf("list: %d %s", rec.Code, rec.Body)
		}
		l, _ := out["templates"].([]any)
		return l
	}
	l := list()
	if len(l) != 5 {
		t.Fatalf("defaults: %d", len(l))
	}
	first, _ := l[0].(map[string]any)
	content, _ := first["content"].(map[string]any)
	body, _ := content["body"].(map[string]any)
	if first["customizable"] != true || first["channel"] != "phone" || first["disabled"] != false || body["text"] == "" || body["voice"] == "" || content["syntax"] != "liquid" {
		t.Fatalf("default template: %v", first)
	}
	rec, created := e.phone(t, "POST", "/x", map[string]any{"type": "otp_verify", "content": map[string]any{"body": map[string]any{"text": "Your {{ code }} for {{ friendly_name }}"}, "from": "ACME"}}, allPhoneScopes, e.h.CreatePhoneTemplate)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	id := created["id"].(string)
	cbody := created["content"].(map[string]any)["body"].(map[string]any)
	if cbody["text"] != "Your {{ code }} for {{ friendly_name }}" || cbody["voice"] == "" || created["type"] != "otp_verify" {
		t.Fatalf("created: %v", created)
	}
	if rec, _ = e.phone(t, "POST", "/x", map[string]any{"type": "otp_verify"}, allPhoneScopes, e.h.CreatePhoneTemplate); rec.Code != 409 {
		t.Fatalf("duplicate type: %d", rec.Code)
	}
	for label, body := range map[string]map[string]any{
		"bad type":    {"type": "marketing"},
		"no type":     {},
		"bad liquid":  {"type": "otp_enroll", "content": map[string]any{"body": map[string]any{"text": "{{ code "}}},
		"empty body":  {"type": "otp_enroll", "content": map[string]any{"body": map[string]any{}}},
		"bad syntax":  {"type": "otp_enroll", "content": map[string]any{"syntax": "mustache"}},
		"long from":   {"type": "otp_enroll", "content": map[string]any{"from": strings.Repeat("a", 17)}},
		"long text":   {"type": "otp_enroll", "content": map[string]any{"body": map[string]any{"text": strings.Repeat("a", 20001)}}},
		"unknown key": {"type": "otp_enroll", "bogus": true},
	} {
		if rec, _ = e.phone(t, "POST", "/x", body, allPhoneScopes, e.h.CreatePhoneTemplate); rec.Code != 400 {
			t.Fatalf("%s: %d %s", label, rec.Code, rec.Body)
		}
	}
	rec, upd := e.phone(t, "PATCH", "/x", map[string]any{"disabled": true, "content": map[string]any{"body": map[string]any{"voice": "Code {{ code }}"}}}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.UpdatePhoneTemplate(w, r, id) })
	ub := upd["content"].(map[string]any)["body"].(map[string]any)
	if rec.Code != 200 || upd["disabled"] != true || ub["voice"] != "Code {{ code }}" || ub["text"] != "Your {{ code }} for {{ friendly_name }}" {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	if len(list()) != 5 {
		t.Fatal("configured type must replace its default, not add")
	}
	rec, reset := e.phone(t, "PATCH", "/x", map[string]any{}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.ResetPhoneTemplate(w, r, id) })
	rb := reset["content"].(map[string]any)["body"].(map[string]any)
	if rec.Code != 200 || rb["text"] != body["text"] || reset["id"] != id {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if rec, _ = e.phone(t, "DELETE", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.DeletePhoneTemplate(w, r, id) }); rec.Code != 204 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec, _ = e.phone(t, "GET", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.GetPhoneTemplate(w, r, id) }); rec.Code != 404 {
		t.Fatalf("get deleted: %d", rec.Code)
	}
	if rec, _ = e.phone(t, "GET", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.GetPhoneTemplate(w, r, "tem_missing") }); rec.Code != 404 {
		t.Fatalf("get missing: %d", rec.Code)
	}
}

func TestPhoneTemplateTry(t *testing.T) {
	e, f := newPhoneEnv(t)
	_, created := e.phone(t, "POST", "/x", map[string]any{"type": "otp_verify", "content": map[string]any{"from": "+15557778888", "body": map[string]any{"text": "T:{{ code }}:{{ friendly_name }}", "voice": "V:{{ code }}"}}}, allPhoneScopes, e.h.CreatePhoneTemplate)
	id := created["id"].(string)
	try := func(body map[string]any) *httptest.ResponseRecorder {
		rec, _ := e.phone(t, "POST", "/x", body, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.TryPhoneTemplate(w, r, id) })
		return rec
	}
	if rec := try(map[string]any{"to": "+14155550100"}); rec.Code != 404 {
		t.Fatalf("no provider: %d %s", rec.Code, rec.Body)
	}
	e.createProvider(t, twilioBody())
	rec := try(map[string]any{"to": "+14155550100"})
	if rec.Code != 202 || f.count() != 1 {
		t.Fatalf("try: %d %s", rec.Code, rec.Body)
	}
	got := f.forms[0]
	if got.Get("From") != "+15557778888" || !strings.HasPrefix(got.Get("Body"), "T:") || strings.Contains(got.Get("Body"), "{{") {
		t.Fatalf("rendered: %v", got)
	}
	if rec = try(map[string]any{"to": "+14155550100", "delivery_method": "voice"}); rec.Code != 202 || f.count() != 2 || !strings.Contains(f.forms[1].Get("Twiml"), "V:") {
		t.Fatalf("voice try: %d %s %v", rec.Code, rec.Body, f.forms)
	}
	// An unconfigured type can be tried by its default id from the list.
	_, l := e.phone(t, "GET", "/x", nil, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) {
		e.h.ListPhoneTemplates(w, r, mgmtapi.ListPhoneTemplatesParams{})
	})
	var defID string
	for _, x := range l["templates"].([]any) {
		m := x.(map[string]any)
		if m["type"] == "otp_enroll" {
			defID, _ = m["id"].(string)
		}
	}
	rec, _ = e.phone(t, "POST", "/x", map[string]any{"to": "+14155550103"}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.TryPhoneTemplate(w, r, defID) })
	// The sample code renders (code-like variables reach the template).
	if defID == "" || rec.Code != 202 || f.count() != 3 || strings.Contains(f.forms[2].Get("Body"), "{{") || !strings.Contains(f.forms[2].Get("Body"), "123456") {
		t.Fatalf("default try: id=%q %d %s %v", defID, rec.Code, rec.Body, f.forms)
	}
}

func TestPhoneProviderProtection(t *testing.T) {
	e, _ := newPhoneEnv(t)
	rec, out := e.phone(t, "GET", "/x", nil, allPhoneScopes, e.h.GetPhoneProviderProtection)
	if rec.Code != 200 || out["type"] != "default" || len(out) != 1 {
		t.Fatalf("default: %d %s", rec.Code, rec.Body)
	}
	rec, out = e.phone(t, "PATCH", "/x", map[string]any{"type": "exponential"}, allPhoneScopes, e.h.UpdatePhoneProviderProtection)
	if rec.Code != 200 || out["type"] != "exponential" {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	rec, out = e.phone(t, "GET", "/x", nil, allPhoneScopes, e.h.GetPhoneProviderProtection)
	if out["type"] != "exponential" {
		t.Fatalf("get after: %s", rec.Body)
	}
	tn, _ := e.st.Tenants().Get(t.Context(), e.tn.ID)
	if tenantrules.PhoneSettingsOf(tn).ProviderProtection != "exponential" {
		t.Fatal("settings do not see protection")
	}
	for label, body := range map[string]any{"bad": map[string]any{"type": "none"}, "empty": map[string]any{}, "extra": map[string]any{"type": "default", "x": 1}} {
		if rec, _ = e.phone(t, "PATCH", "/x", body, allPhoneScopes, e.h.UpdatePhoneProviderProtection); rec.Code != 400 {
			t.Fatalf("%s: %d", label, rec.Code)
		}
	}
	// The protection setting does not leak into, or get set through, tenant settings.
	_, ts := e.phone(t, "GET", "/x", nil, []string{"read:tenant_settings"}, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetTenantSettings(w, r, mgmtapi.GetTenantSettingsParams{})
	})
	if _, ok := ts["phone_provider_protection"]; ok {
		t.Fatal("protection leaked into tenant settings")
	}
}

func TestTenantPhoneSettingsEnforced(t *testing.T) {
	e, _ := newPhoneEnv(t)
	patch := func(body map[string]any) *httptest.ResponseRecorder {
		rec, _ := e.phone(t, "PATCH", "/x", body, []string{"update:tenant_settings"}, e.h.UpdateTenantSettings)
		return rec
	}
	settings := func() tenantrules.PhoneSettings {
		tn, err := e.st.Tenants().Get(t.Context(), e.tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		return tenantrules.PhoneSettingsOf(tn)
	}
	// A tenant that never stored these settings (existing before Plan 34) reads
	// the documented defaults; tenants created now start consolidated (P9).
	def := tenantrules.PhoneSettingsOf(&store.Tenant{})
	if def.Consolidated || !def.DisableSMSObfuscation || def.EnforceClientAuthOnPasswordlessStart || def.CountryCodes != nil || def.ProviderProtection != "default" {
		t.Fatalf("defaults: %+v", def)
	}
	if !settings().Consolidated {
		t.Fatal("tenant created by setup must start consolidated")
	}
	if rec := patch(map[string]any{"phone_consolidated_experience": false}); rec.Code != 200 || settings().Consolidated {
		t.Fatalf("turn off: %d", rec.Code)
	}
	if rec := patch(map[string]any{"phone_consolidated_experience": true, "country_codes": map[string]any{"list": []string{"US", "CA"}, "mode": "allow"}, "flags": map[string]any{"enforce_client_authentication_on_passwordless_start": true, "disable_management_api_sms_obfuscation": false}}); rec.Code != 200 {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	got := settings()
	if !got.Consolidated || got.DisableSMSObfuscation || !got.EnforceClientAuthOnPasswordlessStart || got.CountryCodes == nil || got.CountryCodes.Mode != "allow" || len(got.CountryCodes.List) != 2 {
		t.Fatalf("after: %+v", got)
	}
	if !got.CountryAllowed("US") || got.CountryAllowed("FR") {
		t.Fatalf("allow list not applied: %+v", got)
	}
	patch(map[string]any{"country_codes": map[string]any{"list": []string{"FR"}, "mode": "deny"}})
	if g := settings(); g.CountryAllowed("FR") || !g.CountryAllowed("US") {
		t.Fatalf("deny list not applied: %+v", g)
	}
	for label, body := range map[string]map[string]any{
		"lowercase code": {"country_codes": map[string]any{"list": []string{"us"}, "mode": "allow"}},
		"bad mode":       {"country_codes": map[string]any{"list": []string{"US"}, "mode": "maybe"}},
		"consolidated":   {"phone_consolidated_experience": "yes"},
		"flag type":      {"flags": map[string]any{"disable_management_api_sms_obfuscation": "no"}},
	} {
		if rec := patch(body); rec.Code != 400 {
			t.Fatalf("%s: %d %s", label, rec.Code, rec.Body)
		}
	}
	if rec := patch(map[string]any{"country_codes": nil}); rec.Code != 200 || settings().CountryCodes != nil {
		t.Fatalf("clear: %d", rec.Code)
	}
	// Tenants created now start on the consolidated experience (P9).
	tn, err := tenantsetup.UpsertTenant(t.Context(), e.st, "fresh", e.h.Now(), func(*store.Tenant) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !tenantrules.PhoneSettingsOf(tn).Consolidated {
		t.Fatal("new tenant must default phone_consolidated_experience to true")
	}
}

type noPhoneStore struct{ store.Store }

func (noPhoneStore) Phone() store.Phone { return store.UnimplementedPhone{} }

func TestPhoneRoutesUnavailableOnOldPlugin(t *testing.T) {
	e, _ := newPhoneEnv(t)
	e.h.Store = noPhoneStore{e.st}
	type call struct {
		method string
		body   any
		fn     http.HandlerFunc
	}
	id := "x"
	for name, c := range map[string]call{
		"list providers": {"GET", nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.ListPhoneProviders(w, r, mgmtapi.ListPhoneProvidersParams{})
		}},
		"create provider": {"POST", twilioBody(), e.h.CreatePhoneProvider},
		"get provider":    {"GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetPhoneProvider(w, r, id) }},
		"update provider": {"PATCH", map[string]any{"disabled": true}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdatePhoneProvider(w, r, id) }},
		"delete provider": {"DELETE", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeletePhoneProvider(w, r, id) }},
		"try provider":    {"POST", map[string]any{"to": "+14155550100"}, func(w http.ResponseWriter, r *http.Request) { e.h.TryPhoneProvider(w, r, id) }},
		"list templates": {"GET", nil, func(w http.ResponseWriter, r *http.Request) {
			e.h.ListPhoneTemplates(w, r, mgmtapi.ListPhoneTemplatesParams{})
		}},
		"create template": {"POST", map[string]any{"type": "otp_verify"}, e.h.CreatePhoneTemplate},
		"get template":    {"GET", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetPhoneTemplate(w, r, id) }},
		"update template": {"PATCH", map[string]any{"disabled": true}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdatePhoneTemplate(w, r, id) }},
		"delete template": {"DELETE", nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeletePhoneTemplate(w, r, id) }},
		"reset template":  {"PATCH", map[string]any{}, func(w http.ResponseWriter, r *http.Request) { e.h.ResetPhoneTemplate(w, r, id) }},
		"try template":    {"POST", map[string]any{"to": "+14155550100"}, func(w http.ResponseWriter, r *http.Request) { e.h.TryPhoneTemplate(w, r, id) }},
	} {
		rec, out := e.phone(t, c.method, "/x", c.body, allPhoneScopes, c.fn)
		if rec.Code != 501 || out["errorCode"] != "phone_unavailable" {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

func TestPhoneTryRefusesDisabledProvider(t *testing.T) {
	e, f := newPhoneEnv(t)
	id := e.createProvider(t, twilioBody())["id"].(string)
	e.phone(t, "PATCH", "/x", map[string]any{"disabled": true}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.UpdatePhoneProvider(w, r, id) })
	if rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100"}); rec.Code != 409 {
		t.Fatalf("provider try: %d %s", rec.Code, rec.Body)
	}
	rec, _ := e.phone(t, "POST", "/x", map[string]any{"to": "+14155550100"}, allPhoneScopes, func(w http.ResponseWriter, r *http.Request) { e.h.TryPhoneTemplate(w, r, "tem_default_otp_verify") })
	if rec.Code != 409 || f.count() != 0 {
		t.Fatalf("template try: %d %s sent=%d", rec.Code, rec.Body, f.count())
	}
}

// fakePhoneActions stands in for the Actions engine in try.
type fakePhoneActions struct {
	bound bool
	err   error
	calls []phone.ActionInput
}

func (f *fakePhoneActions) PhoneActionBound(context.Context, string, string) (bool, error) {
	return f.bound, nil
}

func (f *fakePhoneActions) RunPhoneAction(_ context.Context, _ string, in phone.ActionInput) error {
	f.calls = append(f.calls, in)
	return f.err
}

// try on the custom provider runs the bound custom-phone-provider Action.
func TestPhoneProviderTryCustomRunsAction(t *testing.T) {
	e, f := newPhoneEnv(t)
	bindCustomPhoneAction(t, e)
	id := e.createProvider(t, map[string]any{"name": "custom", "credentials": map[string]any{}, "configuration": map[string]any{"delivery_methods": []string{"text", "voice"}}})["id"].(string)
	runner := &fakePhoneActions{}
	e.h.PhoneActions = runner
	if rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100"}); rec.Code != 409 {
		t.Fatalf("unbound custom try: %d %s", rec.Code, rec.Body)
	}
	runner.bound = true
	if rec := e.tryProvider(t, id, map[string]any{"to": "+14155550100", "delivery_method": "voice"}); rec.Code != 202 {
		t.Fatalf("custom try: %d %s", rec.Code, rec.Body)
	}
	if len(runner.calls) != 1 || runner.calls[0].Trigger != phone.TriggerCustomPhoneProvider || runner.calls[0].Message.To != "+14155550100" ||
		runner.calls[0].Message.DeliveryMethod != "voice" || runner.calls[0].AsVoice == "" || f.count() != 0 {
		t.Fatalf("action input = %+v", runner.calls)
	}
	runner.err = &phone.SendError{Class: phone.ClassTransient, Err: errors.New("action failed")}
	if rec := e.tryProvider(t, id, map[string]any{"to": "+14155550101"}); rec.Code != http.StatusBadGateway {
		t.Fatalf("failing action try: %d %s", rec.Code, rec.Body)
	}
}
