package tenantsetup

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// MyAccountAPIName is the My Account API's name (Auth0's, Y2).
const MyAccountAPIName = "Auth0 My Account API"

// MyAccountAPIScopes are the scopes of the My Account API operations
// zeroauthy serves (api/myaccount.yaml).
var MyAccountAPIScopes = []store.Scope{
	{Value: "read:me:authentication_methods", Description: "Read the user's authentication methods"},
	{Value: "create:me:authentication_methods", Description: "Enroll authentication methods for the user"},
	{Value: "update:me:authentication_methods", Description: "Update the user's authentication methods"},
	{Value: "delete:me:authentication_methods", Description: "Delete the user's authentication methods"},
	{Value: "read:me:factors", Description: "Read the factors available to the user"},
}

// ApplyMyAccountAPI gives rs the My Account API's fixed settings
// (LR42a-4): user flows need a client grant, client flows are denied.
func ApplyMyAccountAPI(rs *store.ResourceServer) {
	rs.Name, rs.SigningAlg, rs.IsSystem = MyAccountAPIName, "RS256", true
	rs.Scopes = append([]store.Scope(nil), MyAccountAPIScopes...)
	rs.TokenLifetime = 86400
	rs.TokenLifetimeForWeb = 7200
	rs.AllowOfflineAccess = true
	rs.SkipConsentForVerifiableFirstPartyClients = true
	rs.EnforcePolicies = false
	rs.TokenDialect = "access_token"
	rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyRequireClientGrant, Client: store.PolicyDenyAll}
}

// MyAccountAPI activates t's My Account API (creating or repairing the
// system API) and returns it.
func MyAccountAPI(ctx context.Context, st store.Store, t *store.Tenant, now time.Time) (*store.ResourceServer, error) {
	id := tenant.MyAccountIdentifier(t)
	if id == "" {
		return nil, errors.New("tenantsetup: the tenant has no canonical host, so no My Account API identifier")
	}
	if err := UpsertResourceServer(ctx, st, t.ID, id, now, func(rs *store.ResourceServer) error {
		ApplyMyAccountAPI(rs)
		return nil
	}); err != nil {
		return nil, err
	}
	return st.ResourceServers().GetByIdentifier(ctx, t.ID, id)
}
