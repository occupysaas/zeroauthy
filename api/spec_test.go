package api

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
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

func TestPasskeyWireContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"MFACreateAuthenticationMethod", "MFACreateAuthenticationMethodsResponse", "MFAGetAuthenticationMethodResponse", "MFAUpdateAuthenticationMethodResponse"} {
		schema := doc.Components.Schemas[name].Value.Properties["type"].Value
		if err := schema.VisitJSON("passkey"); err != nil {
			t.Errorf("%s rejects passkey: %v", name, err)
		}
	}
	if err := doc.Components.Schemas["MFASetAuthenticationMethodsRequest"].Value.VisitJSON([]any{map[string]any{"type": "passkey"}}); err == nil {
		t.Fatal("MFA replacement accepts passkeys")
	}
	mobile := doc.Components.Schemas["ClientMobile"].Value
	for _, body := range []any{map[string]any{}, map[string]any{"ios": map[string]any{"team_id": "", "app_bundle_identifier": "bad bundle", "future": true}}, map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []any{"AB"}}}} {
		if err := mobile.VisitJSON(body); err != nil {
			t.Errorf("valid mobile rejected: %v", err)
		}
	}
	for _, body := range []any{nil, map[string]any{"ios": nil}, map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []any{}}}, map[string]any{"android": map[string]any{"sha256_cert_fingerprints": []any{""}}}} {
		if err := mobile.VisitJSON(body); err == nil {
			t.Fatalf("invalid mobile accepted: %v", body)
		}
	}
	if doc.Paths.Find("/api/v2/users/{id}/authentication-methods").Post.Responses.Status(501) == nil {
		t.Fatal("passkey create lacks capability error")
	}
	for _, path := range []string{"/api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites", "/api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings"} {
		item := doc.Paths.Find(path)
		if item == nil || item.Get == nil {
			t.Fatalf("missing extension: %s", path)
		}
	}
}

// Plan 35 freezes the credential, profile and client-authentication
// contracts (D-0063); later tasks implement them.
func TestClientAuthContracts(t *testing.T) {
	mgmt, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]string{
		"/api/v2/clients/{id}/credentials GET":                    "getClientCredentials",
		"/api/v2/clients/{id}/credentials POST":                   "postClientCredentials",
		"/api/v2/clients/{id}/credentials/{credential_id} GET":    "getClientCredential",
		"/api/v2/clients/{id}/credentials/{credential_id} PATCH":  "patchClientCredential",
		"/api/v2/clients/{id}/credentials/{credential_id} DELETE": "deleteClientCredential",
		"/api/v2/token-exchange-profiles GET":                     "getTokenExchangeProfiles",
		"/api/v2/token-exchange-profiles POST":                    "postTokenExchangeProfile",
		"/api/v2/token-exchange-profiles/{id} GET":                "getTokenExchangeProfile",
		"/api/v2/token-exchange-profiles/{id} PATCH":              "patchTokenExchangeProfile",
		"/api/v2/token-exchange-profiles/{id} DELETE":             "deleteTokenExchangeProfile",
	}
	for key, id := range ops {
		path, method, _ := strings.Cut(key, " ")
		item := mgmt.Paths.Find(path)
		if item == nil {
			t.Errorf("%s missing", path)
			continue
		}
		if op := item.GetOperation(method); op == nil || op.OperationID != id {
			t.Errorf("%s %s: operation id is not %s", method, path, id)
		}
	}
	for _, schema := range []struct {
		name  string
		props []string
	}{
		{"Client", []string{"client_authentication_methods", "signed_request_object", "token_exchange"}},
		{"ClientSettings", []string{"client_authentication_methods", "signed_request_object", "token_exchange"}},
		{"ClientCredential", []string{"id", "kid", "alg", "credential_type", "thumbprint_sha256", "expires_at"}},
		{"TokenExchangeProfile", []string{"id", "name", "subject_token_type", "action_id", "type"}},
		{"ResourceServerSettings", []string{"signing_alg", "signing_secret"}},
	} {
		s := mgmt.Components.Schemas[schema.name]
		if s == nil {
			t.Errorf("schema %s missing", schema.name)
			continue
		}
		for _, p := range schema.props {
			if s.Value.Properties[p] == nil {
				t.Errorf("%s.%s missing", schema.name, p)
			}
		}
	}
	if enum := mgmt.Components.Schemas["ResourceServerSettings"].Value.Properties["signing_alg"].Value.Enum; len(enum) != 3 {
		t.Errorf("signing_alg enum = %v, want RS256, HS256, PS256", enum)
	}
	if alg := mgmt.Components.Schemas["ClientCredentialAlg"].Value.Enum; len(alg) != 3 {
		t.Errorf("credential alg enum = %v, want RS256, RS384, PS256", alg)
	}

	auth, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	token := auth.Components.Schemas["TokenRequestFields"].Value
	for _, p := range []string{"client_assertion", "client_assertion_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "requested_token_type"} {
		if token.Properties[p] == nil {
			t.Errorf("TokenRequest.%s missing", p)
		}
	}
	for _, p := range []string{"client_assertion", "client_assertion_type", "request"} {
		if auth.Components.Schemas["PushedAuthorizationRequest"].Value.Properties[p] == nil {
			t.Errorf("PushedAuthorizationRequest.%s missing", p)
		}
	}
	discovery := auth.Components.Schemas["OpenIDConfiguration"].Value
	for _, p := range []string{"request_parameter_supported", "request_object_signing_alg_values_supported", "token_endpoint_auth_signing_alg_values_supported"} {
		if discovery.Properties[p] == nil {
			t.Errorf("OpenIDConfiguration.%s missing", p)
		}
	}
}

// Enterprise SDKs rely on these public key and connection operations; private
// key material has no place in a response schema.
func TestEnterpriseOIDCContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for path, methods := range map[string][]string{
		"/api/v2/connections/{id}/keys":        {"GET", "POST"},
		"/api/v2/connections/{id}/keys/rotate": {"POST"},
		"/api/v2/connections/{id}/status":      {"GET"},
		"/api/v2/connections/{id}/users":       {"DELETE"},
	} {
		item := doc.Paths.Value(path)
		if item == nil {
			t.Errorf("missing %s", path)
			continue
		}
		for _, method := range methods {
			if item.GetOperation(method) == nil {
				t.Errorf("missing %s %s", method, path)
			}
		}
	}
	for _, name := range []string{"ConnectionOptionsOIDC", "ConnectionOptionsOkta", "ConnectionKey"} {
		if doc.Components.Schemas[name] == nil {
			t.Errorf("missing schema %s", name)
		}
	}
	if ref := doc.Components.Schemas["ConnectionKey"]; ref != nil {
		for _, field := range []string{"private_key", "private_sealed", "client_secret"} {
			if ref.Value.Properties[field] != nil {
				t.Errorf("keys expose %s", field)
			}
		}
	}
}

func TestRefreshTokensIIManagementContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, method string
		status       int
	}{
		{"/api/v2/refresh-tokens", "GET", 200},
		{"/api/v2/refresh-tokens/revoke", "POST", 202},
		{"/api/v2/refresh-tokens/{id}", "PATCH", 200},
		{"/api/v2/sessions/{id}", "PATCH", 200},
		{"/api/v2/sessions/{id}/revoke", "POST", 202},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			item := doc.Paths.Find(tc.path)
			if item == nil || item.Operations()[tc.method] == nil {
				t.Fatal("missing operation")
			}
			for _, status := range []int{tc.status, 401, 403} {
				if item.Operations()[tc.method].Responses.Status(status) == nil {
					t.Errorf("missing %d response", status)
				}
			}
		})
	}

	if item := doc.Paths.Find("/api/v2/refresh-tokens"); item != nil && item.Get != nil {
		params := map[string]bool{"user_id": true, "client_id": false, "from": false, "take": false, "fields": false, "include_fields": false}
		for name, required := range params {
			p := item.Get.Parameters.GetByInAndName("query", name)
			if p == nil || p.Required != required {
				t.Errorf("missing query parameter %s or incorrect required flag", name)
			}
		}
		schema := item.Get.Responses.Status(200).Value.Content.Get("application/json").Schema.Value
		if err := schema.VisitJSON(map[string]any{"refresh_tokens": []any{map[string]any{"id": "token-id"}}, "next": "cursor"}); err != nil {
			t.Errorf("projected refresh token page rejected: %v", err)
		}
	}
}

func TestRefreshTokensIIRequestBounds(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	requestSchema := func(t *testing.T, path, method string) *openapi3.Schema {
		t.Helper()
		item := doc.Paths.Find(path)
		if item == nil || item.Operations()[method] == nil {
			t.Fatalf("missing %s %s", method, path)
		}
		return item.Operations()[method].RequestBody.Value.Content.Get("application/json").Schema.Value
	}
	t.Run("bulk revoke", func(t *testing.T) {
		schema := requestSchema(t, "/api/v2/refresh-tokens/revoke", "POST")
		for _, tc := range []struct {
			name  string
			body  map[string]any
			valid bool
		}{
			{"ids", map[string]any{"ids": slices.Repeat([]any{"token-id"}, 100)}, true},
			{"user", map[string]any{"user_id": "auth0|user"}, true},
			{"user and client", map[string]any{"user_id": "auth0|user", "client_id": "app"}, true},
			{"user client and audience", map[string]any{"user_id": "auth0|user", "client_id": "app", "audience": "https://api.example.test"}, true},
			{"missing selector", map[string]any{}, false},
			{"mixed selectors", map[string]any{"ids": []any{"token-id"}, "user_id": "auth0|user"}, false},
			{"client only", map[string]any{"client_id": "app"}, false},
			{"audience without client", map[string]any{"user_id": "auth0|user", "audience": "https://api.example.test"}, false},
			{"too many ids", map[string]any{"ids": slices.Repeat([]any{"token-id"}, 101)}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := schema.VisitJSON(tc.body); (err == nil) != tc.valid {
					t.Errorf("valid=%v, error=%v", tc.valid, err)
				}
			})
		}
	})

	for _, route := range []struct{ path, field string }{
		{"/api/v2/refresh-tokens/{id}", "refresh_token_metadata"},
		{"/api/v2/sessions/{id}", "session_metadata"},
	} {
		t.Run(route.field, func(t *testing.T) {
			schema := requestSchema(t, route.path, "PATCH")
			tooManyProperties := map[string]any{}
			for i := range 26 {
				tooManyProperties[strconv.Itoa(i)] = "value"
			}
			for _, tc := range []struct {
				name     string
				metadata any
				valid    bool
			}{
				{"clear with null", nil, true},
				{"clear with empty", map[string]any{}, true},
				{"max length", map[string]any{strings.Repeat("a", 255): strings.Repeat("b", 255)}, true},
				{"too long key", map[string]any{strings.Repeat("a", 256): "value"}, false},
				{"too long value", map[string]any{"name": strings.Repeat("b", 256)}, false},
				{"too many properties", tooManyProperties, false},
				{"non-string value", map[string]any{"name": 1}, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if err := schema.VisitJSON(map[string]any{route.field: tc.metadata}, openapi3.EnableJSONSchema2020()); (err == nil) != tc.valid {
						t.Errorf("valid=%v, error=%v", tc.valid, err)
					}
				})
			}
		})
	}
}

func TestRefreshTokensIITokenQuotaHeaders(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(AuthenticationYAML)
	if err != nil {
		t.Fatal(err)
	}
	token := doc.Paths.Find("/oauth/token").Post
	for _, status := range []int{200, 429} {
		headers := token.Responses.Status(status).Value.Headers
		for _, name := range []string{"Auth0-Client-Quota-Limit", "Auth0-Organization-Quota-Limit"} {
			if headers[name] == nil {
				t.Errorf("%d missing %s", status, name)
			}
		}
	}
	for _, name := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"} {
		if token.Responses.Status(429).Value.Headers[name] == nil {
			t.Errorf("429 missing %s", name)
		}
	}
}

func TestRefreshTokensIIConfigurationBounds(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	policies := make([]any, 11)
	for i := range policies {
		policies[i] = map[string]any{"audience": "https://api.example.test/" + strconv.Itoa(i), "scope": []any{"read:data"}}
	}
	for _, tc := range []struct {
		name  string
		value any
		valid bool
	}{
		{"clear", nil, true},
		{"maximum policy count", policies[:10], true},
		{"too many policies", policies, false},
		{"empty policies", []any{}, false},
		{"max audience and scope lengths", []any{map[string]any{"audience": strings.Repeat("a", 600), "scope": []any{strings.Repeat("b", 280)}}}, true},
		{"audience too long", []any{map[string]any{"audience": strings.Repeat("a", 601), "scope": []any{"read:data"}}}, false},
		{"scope too long", []any{map[string]any{"audience": "https://api.example.test", "scope": []any{strings.Repeat("b", 281)}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			property := doc.Components.Schemas["RefreshTokenSettings"].Value.Properties["policies"]
			if property == nil {
				t.Fatal("missing refresh_token.policies schema")
			}
			if err := property.Value.VisitJSON(tc.value); (err == nil) != tc.valid {
				t.Errorf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}

	for _, target := range []struct{ schema, field string }{
		{"ClientSettings", "token_quota"},
		{"TenantSettings", "default_token_quota"},
	} {
		t.Run(target.schema, func(t *testing.T) {
			quota := doc.Components.Schemas[target.schema].Value.Properties[target.field]
			if quota == nil {
				t.Fatalf("missing %s", target.field)
			}
			if err := quota.Value.VisitJSON(nil); err != nil {
				t.Errorf("cannot clear quota with null: %v", err)
			}
		})
	}
}

func TestOnlineRefreshTokenResourceServerFlags(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"allow_online_access", "allow_online_access_with_ephemeral_sessions"} {
		t.Run(flag, func(t *testing.T) {
			for _, route := range []struct {
				op   *openapi3.Operation
				body map[string]any
			}{
				{doc.Paths.Find("/api/v2/resource-servers").Post, map[string]any{"identifier": "https://api.example.test", flag: true}},
				{doc.Paths.Find("/api/v2/resource-servers/{id}").Patch, map[string]any{flag: false}},
			} {
				schema := route.op.RequestBody.Value.Content.Get("application/json").Schema.Value
				if err := schema.VisitJSON(route.body); err != nil {
					t.Errorf("%s rejected boolean %s: %v", route.op.OperationID, flag, err)
				}
				route.body[flag] = "true"
				if err := schema.VisitJSON(route.body); err == nil {
					t.Errorf("%s accepted string %s", route.op.OperationID, flag)
				}
			}
			response := doc.Paths.Find("/api/v2/resource-servers/{id}").Get.Responses.Status(200).Value
			prop := response.Content.Get("application/json").Schema.Value.Properties[flag]
			if prop == nil || !prop.Value.Type.Is("boolean") {
				t.Errorf("response must expose %s as a boolean", flag)
			}
		})
	}
}

func TestOrganizationTokenQuotaContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(ManagementYAML)
	if err != nil {
		t.Fatal(err)
	}
	create := doc.Paths.Find("/api/v2/organizations").Post
	item := doc.Paths.Find("/api/v2/organizations/{id}")
	request := func(op *openapi3.Operation) *openapi3.Schema {
		return op.RequestBody.Value.Content.Get("application/json").Schema.Value
	}
	response := func(op *openapi3.Operation, status int) *openapi3.Schema {
		return op.Responses.Status(status).Value.Content.Get("application/json").Schema.Value
	}
	organization := func() map[string]any {
		return map[string]any{
			"id": "org_0123456789abcdef", "name": "acme", "display_name": "Acme",
			"third_party_client_access": "block", "is_app_entitlement_active": false,
		}
	}
	for _, route := range []struct {
		name   string
		schema *openapi3.Schema
		body   map[string]any
	}{
		{"create request", request(create), map[string]any{"name": "acme"}},
		{"update request", request(item.Patch), map[string]any{}},
		{"create response", response(create, 201), organization()},
		{"read response", response(item.Get, 200), organization()},
		{"update response", response(item.Patch, 200), organization()},
	} {
		t.Run(route.name, func(t *testing.T) {
			for _, quota := range []struct {
				name  string
				value any
				valid bool
			}{
				{"bounded quota", map[string]any{"client_credentials": map[string]any{"per_hour": 1, "per_day": 2147483647, "enforce": false}}, true},
				{"clear with null", nil, true},
				{"missing grant", map[string]any{}, false},
				{"empty grant quota", map[string]any{"client_credentials": map[string]any{}}, false},
				{"zero hourly quota", map[string]any{"client_credentials": map[string]any{"per_hour": 0}}, false},
				{"overflow daily quota", map[string]any{"client_credentials": map[string]any{"per_day": float64(2147483648)}}, false},
				{"non-boolean enforcement", map[string]any{"client_credentials": map[string]any{"enforce": "true"}}, false},
			} {
				t.Run(quota.name, func(t *testing.T) {
					route.body["token_quota"] = quota.value
					if err := route.schema.VisitJSON(route.body); (err == nil) != quota.valid {
						t.Errorf("valid=%v, error=%v", quota.valid, err)
					}
				})
			}
		})
	}
}
