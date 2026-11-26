package tenantsetup

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// MyOrgAPIName is the My Organization API's name (the guide's, MO-3).
const MyOrgAPIName = "My Organization API"

// MyOrgTokenLifetime is the fixed access-token lifetime (the guide: 600 s).
const MyOrgTokenLifetime = 600

// MyOrgAPIScopes are the scopes of the Phase A operations zeroauthy serves
// (api/myorg.yaml), with Auth0's descriptions.
var MyOrgAPIScopes = []store.Scope{
	{Value: "read:my_org:configuration", Description: "Read organization configuration"},
	{Value: "read:my_org:details", Description: "Read organization details"},
	{Value: "update:my_org:details", Description: "Update organization details"},
	{Value: "read:my_org:members", Description: "List members for organization"},
	{Value: "delete:my_org:memberships", Description: "Delete members from organization without deleting underlying users"},
	{Value: "read:my_org:member_roles", Description: "List Roles for members in organization"},
	{Value: "create:my_org:member_roles", Description: "Create Roles for members in organization"},
	{Value: "delete:my_org:member_roles", Description: "Delete Roles from members for organization"},
	{Value: "read:my_org:member_invitations", Description: "List member invitations for organization"},
	{Value: "create:my_org:member_invitations", Description: "Create member invitations for organization"},
	{Value: "delete:my_org:member_invitations", Description: "Delete member invitations for organization"},
	{Value: "read:my_org:user_stores", Description: "Read user stores for an organization"},
}

// ApplyMyOrgAPI gives rs the My Organization API's fixed settings: user
// flows need a client grant, client flows are denied, RBAC applies
// (LR42b-5) and tokens live 600 seconds.
func ApplyMyOrgAPI(rs *store.ResourceServer) {
	rs.Name, rs.SigningAlg, rs.IsSystem = MyOrgAPIName, "RS256", true
	rs.Scopes = append([]store.Scope(nil), MyOrgAPIScopes...)
	rs.TokenLifetime, rs.TokenLifetimeForWeb = MyOrgTokenLifetime, MyOrgTokenLifetime
	rs.AllowOfflineAccess = true
	rs.SkipConsentForVerifiableFirstPartyClients = true
	rs.EnforcePolicies = true
	rs.TokenDialect = "access_token"
	rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyRequireClientGrant, Client: store.PolicyDenyAll}
}

// MyOrgAPI activates t's My Organization API and returns it.
func MyOrgAPI(ctx context.Context, st store.Store, t *store.Tenant, now time.Time) (*store.ResourceServer, error) {
	id := tenant.MyOrgIdentifier(t)
	if id == "" {
		return nil, errors.New("tenantsetup: the tenant has no canonical host, so no My Organization API identifier")
	}
	if err := UpsertResourceServer(ctx, st, t.ID, id, now, func(rs *store.ResourceServer) error {
		ApplyMyOrgAPI(rs)
		return nil
	}); err != nil {
		return nil, err
	}
	return st.ResourceServers().GetByIdentifier(ctx, t.ID, id)
}
