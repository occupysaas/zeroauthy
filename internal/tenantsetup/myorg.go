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

// MyOrgAPIScopes are the scopes of the operations zeroauthy serves
// (api/myorg.yaml: Phase A, D-0220; Phase B, D-0221), with Auth0's
// descriptions.
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
	{Value: "read:my_org:domains", Description: "Read domains for organization"},
	{Value: "create:my_org:domains", Description: "Create domain for organization"},
	{Value: "update:my_org:domains", Description: "Update domain for organization"},
	{Value: "delete:my_org:domains", Description: "Delete domain for organization"},
	{Value: "read:my_org:identity_providers", Description: "Read identity providers for organization"},
	{Value: "create:my_org:identity_providers", Description: "Create identity provider for organization"},
	{Value: "update:my_org:identity_providers", Description: "Update identity provider for organization"},
	{Value: "delete:my_org:identity_providers", Description: "Delete identity provider for organization"},
	{Value: "update:my_org:identity_providers_detach", Description: "Detach identity provider from organization"},
	{Value: "create:my_org:identity_providers_domains", Description: "Associate organization domain with identity provider"},
	{Value: "delete:my_org:identity_providers_domains", Description: "Remove organization domain from identity provider"},
	{Value: "read:my_org:identity_providers_provisioning", Description: "Read provisioning configuration for identity provider"},
	{Value: "create:my_org:identity_providers_provisioning", Description: "Create provisioning configuration for identity provider"},
	{Value: "update:my_org:identity_providers_provisioning", Description: "Update provisioning configuration for identity provider"},
	{Value: "delete:my_org:identity_providers_provisioning", Description: "Delete provisioning configuration for identity provider"},
	{Value: "read:my_org:identity_providers_scim_tokens", Description: "List the provisioning SCIM tokens for this identity provider"},
	{Value: "create:my_org:identity_providers_scim_tokens", Description: "Create a provisioning SCIM token for this identity provider"},
	{Value: "delete:my_org:identity_providers_scim_tokens", Description: "Delete a provisioning SCIM configuration for an identity provider"},
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

// UpgradeMyOrgAPIScopes adds newly served scopes (Phase B, D-0221) to an
// activated My Organization API, keeping its other settings. Tenants that
// have not activated it are untouched.
func UpgradeMyOrgAPIScopes(ctx context.Context, st store.Store, t *store.Tenant) error {
	if t == nil || t.Reserved {
		return nil
	}
	id := tenant.MyOrgIdentifier(t)
	if id == "" {
		return nil
	}
	return st.WithTx(ctx, func(tx store.Store) error {
		api, err := tx.ResourceServers().GetByIdentifier(ctx, t.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil || !api.IsSystem {
			return err
		}
		seen := make(map[string]bool, len(api.Scopes))
		for _, s := range api.Scopes {
			seen[s.Value] = true
		}
		changed := false
		for _, s := range MyOrgAPIScopes {
			if !seen[s.Value] {
				api.Scopes, seen[s.Value], changed = append(api.Scopes, s), true, true
			}
		}
		if !changed {
			return nil
		}
		return tx.ResourceServers().Update(ctx, api)
	})
}
