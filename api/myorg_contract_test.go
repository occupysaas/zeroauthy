package api

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestMyOrgContracts pins Plan 42b Phase A (D-0220): the operations and
// scopes of Auth0's My Organization OpenAPI 1.0.0 zeroauthy serves.
func TestMyOrgContracts(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromData(MyOrgYAML)
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Servers[0].URL; got != "https://{host}/my-org/v1" {
		t.Errorf("server %q", got)
	}
	ops := []struct{ method, path, scope string }{
		{"GET", "/config", "read:my_org:configuration"},
		{"GET", "/details", "read:my_org:details"},
		{"PATCH", "/details", "update:my_org:details"},
		{"GET", "/members", "read:my_org:members"},
		{"GET", "/members/{user_id}", "read:my_org:members"},
		{"POST", "/delete-memberships", "delete:my_org:memberships"},
		{"GET", "/members/{user_id}/roles", "read:my_org:member_roles"},
		{"POST", "/members/{user_id}/roles", "create:my_org:member_roles"},
		{"POST", "/members/{user_id}/unassign-roles", "delete:my_org:member_roles"},
		{"GET", "/roles", "read:my_org:member_roles"},
		{"GET", "/member-invitations", "read:my_org:member_invitations"},
		{"POST", "/member-invitations", "create:my_org:member_invitations"},
		{"GET", "/member-invitations/{invitation_id}", "read:my_org:member_invitations"},
		{"GET", "/member-invitations/{invitation_id}/roles", "read:my_org:member_roles"},
		{"POST", "/delete-member-invitations", "delete:my_org:member_invitations"},
		{"GET", "/user-stores", "read:my_org:user_stores"},
	}
	n := 0
	for _, item := range doc.Paths.Map() {
		n += len(item.Operations())
	}
	if n != len(ops) {
		t.Errorf("%d operations, want %d (Phase B is not served)", n, len(ops))
	}
	for _, c := range ops {
		item := doc.Paths.Value(c.path)
		if item == nil || item.GetOperation(c.method) == nil {
			t.Errorf("%s %s missing", c.method, c.path)
			continue
		}
		sec := item.GetOperation(c.method).Security
		if sec == nil || len(*sec) != 1 || len((*sec)[0]["myOrgToken"]) != 1 || (*sec)[0]["myOrgToken"][0] != c.scope {
			t.Errorf("%s %s: scope must be %s", c.method, c.path, c.scope)
		}
	}
	for _, f := range []string{"type", "status", "title", "detail", "validation_errors"} {
		if doc.Components.Schemas["ErrorResponse"].Value.Properties[f] == nil {
			t.Errorf("ErrorResponse.%s missing", f)
		}
	}
}
