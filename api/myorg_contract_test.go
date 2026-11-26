package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestMyOrgContracts pins Plan 42b (D-0220, D-0221): the operations and
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
		// Phase B (D-0221).
		{"GET", "/config/identity-providers", "read:my_org:configuration"},
		{"GET", "/domains", "read:my_org:domains"},
		{"POST", "/domains", "create:my_org:domains"},
		{"GET", "/domains/{domain_id}", "read:my_org:domains"},
		{"DELETE", "/domains/{domain_id}", "delete:my_org:domains"},
		{"POST", "/domains/{domain_id}/verify", "update:my_org:domains"},
		{"GET", "/domains/{domain_id}/identity-providers", "read:my_org:domains read:my_org:identity_providers"},
		{"GET", "/identity-providers", "read:my_org:identity_providers"},
		{"POST", "/identity-providers", "create:my_org:identity_providers"},
		{"GET", "/identity-providers/{idp_id}", "read:my_org:identity_providers"},
		{"PATCH", "/identity-providers/{idp_id}", "update:my_org:identity_providers"},
		{"DELETE", "/identity-providers/{idp_id}", "delete:my_org:identity_providers"},
		{"PUT", "/identity-providers/{idp_id}/update-attributes", "update:my_org:identity_providers"},
		{"POST", "/identity-providers/{idp_id}/detach", "update:my_org:identity_providers_detach"},
		{"POST", "/identity-providers/{idp_id}/domains", "create:my_org:identity_providers_domains"},
		{"DELETE", "/identity-providers/{idp_id}/domains/{domain}", "delete:my_org:identity_providers_domains"},
		{"GET", "/identity-providers/{idp_id}/provisioning", "read:my_org:identity_providers_provisioning"},
		{"POST", "/identity-providers/{idp_id}/provisioning", "create:my_org:identity_providers_provisioning"},
		{"DELETE", "/identity-providers/{idp_id}/provisioning", "delete:my_org:identity_providers_provisioning"},
		{"PUT", "/identity-providers/{idp_id}/provisioning/update-attributes", "update:my_org:identity_providers_provisioning"},
		{"GET", "/identity-providers/{idp_id}/provisioning/scim-tokens", "read:my_org:identity_providers_scim_tokens"},
		{"POST", "/identity-providers/{idp_id}/provisioning/scim-tokens", "create:my_org:identity_providers_scim_tokens"},
		{"GET", "/identity-providers/{idp_id}/provisioning/scim-tokens/{idp_scim_token_id}", "read:my_org:identity_providers_scim_tokens"},
		{"DELETE", "/identity-providers/{idp_id}/provisioning/scim-tokens/{idp_scim_token_id}", "delete:my_org:identity_providers_scim_tokens"},
	}
	n := 0
	for _, item := range doc.Paths.Map() {
		n += len(item.Operations())
	}
	if n != len(ops) {
		t.Errorf("%d operations, want %d", n, len(ops))
	}
	for _, c := range ops {
		item := doc.Paths.Value(c.path)
		if item == nil || item.GetOperation(c.method) == nil {
			t.Errorf("%s %s missing", c.method, c.path)
			continue
		}
		op := item.GetOperation(c.method)
		sec := op.Security
		if sec == nil || len(*sec) != 1 || strings.Join((*sec)[0]["myOrgToken"], " ") != c.scope {
			t.Errorf("%s %s: scope must be %s", c.method, c.path, c.scope)
		}
		if src, _ := op.Extensions["x-source"].([]any); len(src) == 0 || !strings.HasPrefix(fmt.Sprint(src[0]), "https://") {
			t.Errorf("%s %s: x-source missing", c.method, c.path)
		}
	}
	for _, f := range []string{"type", "status", "title", "detail", "validation_errors"} {
		if doc.Components.Schemas["ErrorResponse"].Value.Properties[f] == nil {
			t.Errorf("ErrorResponse.%s missing", f)
		}
	}
}
