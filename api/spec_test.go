package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

var specs = map[string][]byte{"authentication.yaml": AuthenticationYAML, "management.yaml": ManagementYAML}

func TestSpecsAreValid(t *testing.T) {
	for name, data := range specs {
		doc, err := openapi3.NewLoader().LoadFromData(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := doc.Validate(context.Background()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The shared Management API parts later operations reference.
func TestManagementSpecShared(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"page", "per_page", "include_totals", "fields", "include_fields"} {
		if doc.Components.Parameters[p] == nil {
			t.Errorf("parameter %q missing", p)
		}
	}
	if pp := doc.Components.Parameters["per_page"]; pp != nil && (pp.Value.Schema.Value.Max == nil || *pp.Value.Schema.Value.Max != 100) {
		t.Error("per_page maximum is not 100")
	}
	e := doc.Components.Schemas["ManagementError"]
	if e == nil {
		t.Fatal("ManagementError missing")
	}
	for _, f := range []string{"statusCode", "error", "message", "errorCode"} {
		if e.Value.Properties[f] == nil {
			t.Errorf("ManagementError.%s missing", f)
		}
	}
	for _, s := range []string{"managementToken", "operatorToken"} {
		if doc.Components.SecuritySchemes[s] == nil {
			t.Errorf("security scheme %q missing", s)
		}
	}
}

// Every operation must cite the public sources it was derived from
// (CLEAN_ROOM.md, "Provenance").
func TestEveryOperationHasProvenance(t *testing.T) {
	for name, data := range specs {
		t.Run(name, func(t *testing.T) { checkProvenance(t, data) })
	}
}

func checkProvenance(t *testing.T, data []byte) {
	doc, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			raw, ok := op.Extensions["x-source"]
			if !ok {
				t.Errorf("%s %s: missing x-source", method, path)
				continue
			}
			b, _ := json.Marshal(raw)
			var urls []string
			if err := json.Unmarshal(b, &urls); err != nil || len(urls) == 0 {
				t.Errorf("%s %s: x-source must be a non-empty list of URLs, got %s", method, path, b)
				continue
			}
			for _, u := range urls {
				if !strings.HasPrefix(u, "https://") {
					t.Errorf("%s %s: x-source %q is not an https URL", method, path, u)
				}
			}
		}
	}
}

// Write-only credentials belong exclusively to request schemas; patch preserves omitted secrets.
func TestEventStreamCredentialContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ auth, secret string }{{"Basic", "password"}, {"Bearer", "token"}, {"CustomHeader", "header_value"}} {
		for _, mode := range []string{"Create", "Patch"} {
			name := "EventsEventStreamWebhook" + tc.auth + "Auth" + mode
			ref := doc.Components.Schemas[name]
			if ref == nil {
				t.Errorf("missing %s", name)
				continue
			}
			secret := ref.Value.Properties[tc.secret]
			if secret == nil || !secret.Value.WriteOnly {
				t.Errorf("%s missing write-only %s", name, tc.secret)
			}
			required := false
			for _, k := range ref.Value.Required {
				required = required || k == tc.secret
			}
			if required != (mode == "Create") {
				t.Errorf("%s secret requirement = %v", name, required)
			}
		}
		response := doc.Components.Schemas["EventsEventStreamWebhook"+tc.auth+"Auth"]
		if response.Value.Properties[tc.secret] != nil {
			t.Errorf("response contains %s", tc.secret)
		}
	}
}

func TestEventStreamSubscriptionRequests(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"EventsCreateEventStreamWebHookRequestContent", "EventsUpdateEventStreamRequestContent"} {
		schema := doc.Components.Schemas[name].Value
		for _, tc := range []struct {
			name         string
			subscription map[string]any
			valid        bool
		}{
			{"known", map[string]any{"event_type": "user.created"}, true},
			{"missing", map[string]any{}, false},
			{"unknown", map[string]any{"event_type": "user.invented"}, false},
		} {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				body := map[string]any{"name": "sync", "subscriptions": []any{tc.subscription}, "destination": map[string]any{"type": "webhook", "configuration": map[string]any{"webhook_endpoint": "https://example.com/events", "webhook_authorization": map[string]any{"method": "bearer", "token": "secret"}}}}
				err := schema.VisitJSON(body)
				if (err == nil) != tc.valid {
					t.Fatalf("valid=%v, error=%v", tc.valid, err)
				}
			})
		}
	}
}

// MFA contracts are documentation-only in Task 1; responses must never expose
// enrollment credentials even when requests accept them.
func TestMFASecretBoundary(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	create := doc.Components.Schemas["MFACreateAuthenticationMethod"]
	if create == nil {
		t.Fatal("missing MFA create schema")
	}
	secret := create.Value.Properties["totp_secret"]
	if secret == nil || !secret.Value.WriteOnly {
		t.Fatal("totp_secret must be write-only")
	}
	method := doc.Components.Schemas["MFAAuthenticationMethod"]
	if method == nil || method.Value.Properties["totp_secret"] != nil {
		t.Fatal("public methods expose totp_secret")
	}
}

func TestMFAWireContracts(t *testing.T) {
	auth, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	response := auth.Paths.Find("/oauth/token").Post.Responses.Status(403).Value.Content.Get("application/json").Schema.Value
	if err := response.VisitJSON(map[string]any{"error": "mfa_required", "error_description": "Multifactor authentication required", "mfa_token": "token"}); err != nil {
		t.Errorf("MFA required response rejected: %v", err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	policy := doc.Components.Schemas["MFASetGuardianPoliciesRequest"].Value
	for _, tc := range []struct {
		body  []any
		valid bool
	}{{[]any{}, true}, {[]any{"all-applications"}, true}, {[]any{"all-applications", "confidence-score"}, false}} {
		if err := policy.VisitJSON(tc.body); (err == nil) != tc.valid {
			t.Errorf("policy %v: valid=%v, error=%v", tc.body, tc.valid, err)
		}
	}
	item := doc.Paths.Find("/api/v2/guardian/enrollments/{id}")
	for method, op := range map[string]*openapi3.Operation{"GET": item.Get, "DELETE": item.Delete} {
		if op.Responses.Status(404) == nil {
			t.Errorf("%s enrollment missing 404", method)
		}
	}
	for _, name := range []string{"MFAUpdateGuardianFactorsPushNotificationProvidersFcmv1Request", "MFASetGuardianFactorsPushNotificationProvidersFcmv1Request"} {
		if p := doc.Components.Schemas[name].Value.Properties["server_credentials"]; p == nil || !p.Value.WriteOnly {
			t.Errorf("%s credentials must be write-only", name)
		}
	}
}

// Plan 34 contracts: phone credentials are write-only, passwordless routes and
// the OTP grant are documented, and connection strategies include email and sms.
func TestPhoneWireContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for path, methods := range map[string][]string{
		"/api/v2/branding/phone/providers":                    {"GET", "POST"},
		"/api/v2/branding/phone/providers/{id}":               {"GET", "PATCH", "DELETE"},
		"/api/v2/branding/phone/providers/{id}/try":           {"POST"},
		"/api/v2/branding/phone/templates":                    {"GET", "POST"},
		"/api/v2/branding/phone/templates/{id}":               {"GET", "PATCH", "DELETE"},
		"/api/v2/branding/phone/templates/{id}/reset":         {"PATCH"},
		"/api/v2/branding/phone/templates/{id}/try":           {"POST"},
		"/api/v2/attack-protection/phone-provider-protection": {"GET", "PATCH"},
	} {
		item := doc.Paths.Find(path)
		for _, m := range methods {
			if item == nil || item.GetOperation(m) == nil {
				t.Errorf("missing %s %s", m, path)
			}
		}
	}
	for _, name := range []string{"PhoneProviderCreate", "PhoneProviderUpdate"} {
		s := doc.Components.Schemas[name]
		if s == nil {
			t.Errorf("missing %s", name)
			continue
		}
		creds := s.Value.Properties["credentials"]
		if creds == nil || !creds.Value.WriteOnly {
			t.Errorf("%s credentials must be write-only", name)
		}
	}
	if p := doc.Components.Schemas["PhoneProvider"]; p == nil || p.Value.Properties["credentials"] != nil {
		t.Error("phone provider responses must not carry credentials")
	}
	for _, name := range []string{"ConnectionOptionsEmail", "ConnectionOptionsSMS"} {
		if doc.Components.Schemas[name] == nil {
			t.Errorf("missing %s", name)
		}
	}
	if s := doc.Components.Schemas["ConnectionOptionsSMS"]; s != nil {
		if tok := s.Value.Properties["twilio_token"]; tok == nil || !tok.Value.WriteOnly {
			t.Error("twilio_token must be write-only")
		}
	}
	strategies := doc.Components.Schemas["ConnectionCreate"].Value.AllOf[1].Value.Properties["strategy"].Value.Enum
	for _, want := range []string{"email", "sms"} {
		found := false
		for _, s := range strategies {
			found = found || s == want
		}
		if !found {
			t.Errorf("strategy %s not creatable", want)
		}
	}
	auth, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Paths.Find("/passwordless/start") == nil || auth.Paths.Find("/passwordless/start").Post == nil {
		t.Error("missing POST /passwordless/start")
	}
	if item := auth.Paths.Find("/passwordless/verify_redirect"); item == nil || item.Get == nil || item.Post == nil {
		t.Error("missing /passwordless/verify_redirect GET and POST")
	}
	token := auth.Paths.Find("/oauth/token").Post
	grants, _ := json.Marshal(token.Extensions["x-passwordless-grants"])
	if !strings.Contains(string(grants), "http://auth0.com/oauth/grant-type/passwordless/otp") {
		t.Error("passwordless OTP grant not documented")
	}
}
