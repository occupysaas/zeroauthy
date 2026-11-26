package api

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestMyAccountContracts pins Plan 42a's contract (D-0210): the seven
// My Account operations, their scopes and the error body.
func TestMyAccountContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(MyAccountYAML)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Servers[0].URL; got != "https://{host}/me/v1" {
		t.Errorf("server %q", got)
	}
	for _, c := range []struct{ method, path, scope string }{
		{"GET", "/factors", "read:me:factors"},
		{"GET", "/authentication-methods", "read:me:authentication_methods"},
		{"POST", "/authentication-methods", "create:me:authentication_methods"},
		{"GET", "/authentication-methods/{authentication_method_id}", "read:me:authentication_methods"},
		{"PATCH", "/authentication-methods/{authentication_method_id}", "update:me:authentication_methods"},
		{"DELETE", "/authentication-methods/{authentication_method_id}", "delete:me:authentication_methods"},
		{"POST", "/authentication-methods/{authentication_method_id}/verify", "create:me:authentication_methods"},
	} {
		item := doc.Paths.Value(c.path)
		if item == nil || item.GetOperation(c.method) == nil {
			t.Errorf("%s %s missing", c.method, c.path)
			continue
		}
		op := item.GetOperation(c.method)
		if op.Security == nil || len(*op.Security) != 1 || len((*op.Security)[0]["myAccountToken"]) != 1 || (*op.Security)[0]["myAccountToken"][0] != c.scope {
			t.Errorf("%s %s: scope must be %s", c.method, c.path, c.scope)
		}
	}
	if n := len(doc.Paths.Map()); n != 4 {
		t.Errorf("%d paths; connected accounts, consents and profile are not served", n)
	}
	e := doc.Components.Schemas["ErrorResponse"]
	if e == nil {
		t.Fatal("ErrorResponse missing")
	}
	for _, f := range []string{"type", "status", "title", "detail", "validation_errors"} {
		if e.Value.Properties[f] == nil {
			t.Errorf("ErrorResponse.%s missing", f)
		}
	}
	if got := doc.Components.Schemas["FactorType"].Value.Enum; len(got) != 9 {
		t.Errorf("FactorType %v", got)
	}
}
