package tenantsetup

import "testing"

// Every invitation HTTP scope must be issuable by normal tenant credentials,
// not merely accepted by a router supplied with a synthetic bearer token.
func TestOrganizationsIIInvitationScopesIssuable(t *testing.T) {
	for _, required := range []string{"read:organization_invitations", "create:organization_invitations", "delete:organization_invitations"} {
		found := false
		for _, scope := range ManagementAPIScopes {
			if scope.Value == required {
				found = true
			}
		}
		if !found {
			t.Errorf("invitation scope %q cannot be provisioned", required)
		}
	}
}
