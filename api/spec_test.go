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
