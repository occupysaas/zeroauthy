package phonerules_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logrules"
	"github.com/zeroauthy/zeroauthy/internal/phonerules"
)

// Every route in spec §3–§7 must be frozen before runtime tasks consume it.
func TestPhoneInventory(t *testing.T) {
	routes := []string{
		// §3 passwordless connections and the Authentication API.
		"POST /api/v2/connections#email", "POST /api/v2/connections#sms",
		"PATCH /api/v2/connections/{id}#email", "PATCH /api/v2/connections/{id}#sms",
		"POST /passwordless/start", "GET /passwordless/verify_redirect", "POST /passwordless/verify_redirect",
		"passwordless-otp",
		// §4 phone messaging.
		"GET /api/v2/branding/phone/providers", "POST /api/v2/branding/phone/providers",
		"GET /api/v2/branding/phone/providers/{id}", "PATCH /api/v2/branding/phone/providers/{id}",
		"DELETE /api/v2/branding/phone/providers/{id}", "POST /api/v2/branding/phone/providers/{id}/try",
		"GET /api/v2/branding/phone/templates", "POST /api/v2/branding/phone/templates",
		"GET /api/v2/branding/phone/templates/{id}", "PATCH /api/v2/branding/phone/templates/{id}",
		"DELETE /api/v2/branding/phone/templates/{id}", "PATCH /api/v2/branding/phone/templates/{id}/reset",
		"POST /api/v2/branding/phone/templates/{id}/try",
		// §6 SMS and voice MFA.
		"PUT /api/v2/guardian/factors/{name}#sms", "PUT /api/v2/guardian/factors/{name}#phone",
		"GET /api/v2/guardian/factors/phone/message-types", "PUT /api/v2/guardian/factors/phone/message-types",
		"GET /api/v2/guardian/factors/phone/selected-provider", "PUT /api/v2/guardian/factors/phone/selected-provider",
		"GET /api/v2/guardian/factors/sms/selected-provider", "PUT /api/v2/guardian/factors/sms/selected-provider",
		"GET /api/v2/users/{id}/enrollments", "POST /mfa/associate#phone", "POST /mfa/challenge#phone", "mfa-oob#phone",
		// §7 phone identifiers and reset; §10 tenant protection.
		"POST /dbconnections/signup#phone", "PATCH /api/v2/users/{id}#phone_number",
		"GET /api/v2/attack-protection/phone-provider-protection", "PATCH /api/v2/attack-protection/phone-provider-protection",
	}
	for _, op := range routes {
		r := phonerules.Route(op)
		if r.Operation != op && r.Method+" "+r.Path != op {
			t.Errorf("missing route %s", op)
			continue
		}
		if !strings.HasPrefix(r.Source, "https://") || r.Scopes == nil || r.Parameters == nil || r.Body == nil || len(r.Errors) == 0 {
			t.Errorf("incomplete %s: %+v", op, r)
		}
		if strings.HasPrefix(r.Path, "/api/v2/") && len(r.Scopes) == 0 {
			t.Errorf("management scope missing: %s", op)
		}
	}
	for _, s := range []struct{ strategy, sealed string }{{"sms", "twilio_token"}, {"sms", "gateway_authentication.secret"}} {
		schema := phonerules.ConnectionOptions(s.strategy)
		if schema.Strategy != s.strategy || !slices.Contains(schema.Sealed, s.sealed) || schema.Options == nil || schema.Source == "" {
			t.Errorf("%s options missing sealed %s: %+v", s.strategy, s.sealed, schema)
		}
	}
	email := phonerules.ConnectionOptions("email")
	if email.Strategy != "email" || email.Options == nil || email.Defaults["totp"] == nil || len(email.Sealed) != 0 {
		t.Errorf("email options: %+v", email)
	}
	if sms := phonerules.ConnectionOptions("sms"); !slices.Contains(sms.ConsolidatedOverrides, "twilio_sid") || slices.Contains(sms.ConsolidatedOverrides, "totp") {
		t.Errorf("consolidated overrides: %v", sms.ConsolidatedOverrides)
	}
	wantProviders := []phonerules.Provider{
		{Name: "twilio", Extension: false, DeliveryMethods: []string{"text", "voice"}},
		{Name: "custom", Extension: false, DeliveryMethods: []string{"text", "voice"}},
		{Name: "sns", Extension: true, DeliveryMethods: []string{"text"}},
	}
	if got := phonerules.ProviderNames(); !reflect.DeepEqual(got, wantProviders) {
		t.Errorf("providers: %+v", got)
	}
	types := map[string]bool{}
	for _, tt := range phonerules.TemplateTypes() {
		types[tt.Type] = true
		if tt.Default.Body.Text == "" || tt.Default.Syntax != "liquid" || len(tt.Variables) == 0 {
			t.Errorf("template %s lacks default or variables: %+v", tt.Type, tt)
		}
		if tt.Type != "blocked_account" && !strings.Contains(tt.Default.Body.Text, "{{ code }}") {
			t.Errorf("template %s default omits code", tt.Type)
		}
		if tt.Type == "blocked_account" && slices.Contains(tt.Variables, "code") {
			t.Error("blocked_account must not offer code")
		}
	}
	for _, typ := range []string{"otp_verify", "otp_enroll", "change_password", "blocked_account", "password_breach"} {
		if !types[typ] {
			t.Errorf("template type %s missing", typ)
		}
	}
	type key struct {
		purpose      string
		consolidated bool
		guardian     string
	}
	covered := map[key]bool{}
	for _, r := range phonerules.Routing() {
		if r.Sender == "" || r.Template == "" {
			t.Errorf("routing rule without sender/template: %+v", r)
		}
		covered[key{r.Purpose, r.Consolidated, r.GuardianProvider}] = true
	}
	for _, consolidated := range []bool{true, false} {
		for _, g := range []string{"auth0", "twilio", "phone-message-hook"} {
			if !covered[key{"mfa", consolidated, g}] {
				t.Errorf("routing missing mfa consolidated=%v guardian=%s", consolidated, g)
			}
		}
		for _, p := range []string{"passwordless", "reset", "verify"} {
			if !covered[key{p, consolidated, ""}] {
				t.Errorf("routing missing %s consolidated=%v", p, consolidated)
			}
		}
	}
	screens := phonerules.Screens()
	for prompt, want := range map[string][]string{
		"login-passwordless":          {"login-passwordless-email-code", "login-passwordless-email-link", "login-passwordless-sms-otp"},
		"mfa-sms":                     {"mfa-country-codes", "mfa-sms-enrollment", "mfa-sms-challenge", "mfa-sms-list"},
		"mfa-voice":                   {"mfa-voice-enrollment", "mfa-voice-challenge"},
		"mfa-phone":                   {"mfa-phone-enrollment", "mfa-phone-challenge"},
		"phone-identifier-enrollment": {"phone-identifier-enrollment"},
		"phone-identifier-challenge":  {"phone-identifier-challenge"},
	} {
		if !reflect.DeepEqual(screens[prompt], want) {
			t.Errorf("screens %s = %v", prompt, screens[prompt])
		}
	}
	for _, id := range []string{"custom-phone-provider", "send-phone-message"} {
		tr := phonerules.ActionTrigger(id)
		if tr.ID != id || tr.Handler == "" || len(tr.Event) == 0 || len(tr.API) == 0 || tr.Source == "" {
			t.Errorf("trigger %s incomplete: %+v", id, tr)
		}
	}
	if tr := phonerules.ActionTrigger("custom-phone-provider"); !slices.Contains(tr.API, "notification.drop") || !slices.Contains(tr.Event, "notification.as_voice") {
		t.Errorf("custom-phone-provider members: %+v", tr)
	}
	l := phonerules.Limits
	if l.OTPLengthDefault != 6 || l.OTPLengthMin != 4 || l.OTPLengthMax != 40 || l.OTPLifetimeDefaultSeconds != 180 || l.OTPLifetimeMinSeconds != 60 ||
		l.OTPAttempts != 3 || l.LinkLifetimeDefaultSeconds != 180 || l.StartPerIPPerHour != 50 || l.PhoneSendsPerUserPerHour != 10 ||
		l.SignupOTPLifetimeSeconds != 900 || l.SignupOTPSendsPerHour <= 0 || l.IdentifierSendsPerHour <= 0 || l.GatewayTimeoutSeconds != 30 ||
		l.CustomProviderRetries != 5 || l.BackoffMaxSeconds != 1920 || l.TemplateBodyMax != 20000 || l.PhoneNumberMax != 16 {
		t.Errorf("limits %+v", l)
	}
	inv := phonerules.Inventory()
	if inv.Decision != "D-0060" || len(inv.Gaps) == 0 || inv.Gaps[0] != "P1" {
		t.Errorf("decision/gaps: %s %v", inv.Decision, inv.Gaps)
	}
}

// The documented example masks every character but the last four.
func TestMaskPhone(t *testing.T) {
	for in, want := range map[string]string{
		"+15555556220":  "XXXXXXXX6220",
		"+442071838750": "XXXXXXXXX8750",
		"+123":          "XXXX",
		"":              "",
	} {
		if got := phonerules.MaskPhone(in); got != want {
			t.Errorf("MaskPhone(%q) = %q, want %q", in, got, want)
		}
	}
	if r := phonerules.Inventory().Masking; r.Visible != 4 || r.Char != "X" || !strings.HasPrefix(r.Source, "https://") {
		t.Errorf("masking rule %+v", r)
	}
}

var plan34Codes = []string{"cs", "cls", "fepotpft", "gd_send_sms", "gd_send_sms_failure", "gd_send_voice", "gd_send_voice_failure", "gd_phone_settings_update", "limit_phone", "limit_signup_otp", "scpn", "fcpn"}

func TestPlan34LogCodes(t *testing.T) {
	codes := map[string]logrules.Code{}
	for _, c := range logrules.Codes() {
		codes[c.Type] = c
	}
	for _, code := range plan34Codes {
		c, ok := codes[code]
		if !ok {
			t.Errorf("missing code %s", code)
			continue
		}
		if c.Plan != 34 || !strings.HasPrefix(c.Source, "https://auth0.com/docs/tenant-logs/") {
			t.Errorf("%s owner/source: %+v", code, c)
		}
		if !strings.Contains(phonerules.Inventory().LogCodes[code], " ") {
			t.Errorf("%s has no frozen Plan 34 emission rule", code)
		}
	}
	// Reused codes keep their earlier owners; the inventory names when Plan 34 emits them.
	for _, code := range []string{"s", "f", "fu", "ss", "fs", "fn", "api_limit", "depnote", "limit_wc"} {
		if _, ok := codes[code]; !ok || phonerules.Inventory().LogCodes[code] == "" {
			t.Errorf("reused code %s not mapped", code)
		}
	}
	for _, code := range plan34Codes {
		c := codes[code]
		if !c.Emitted || c.Status != "emitted" || len(c.Triggers) == 0 {
			t.Errorf("%s not emitted by Plan 34", code)
		}
	}
}
