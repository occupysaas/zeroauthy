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
