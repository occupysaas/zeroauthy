package tenantsetup

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// ManagementAPIName is the name of each tenant's Management API resource
// server (Auth0 lists its own as "Auth0 Management API").
const ManagementAPIName = "Auth0 Management API"

// ManagementAPIScopes are the Management API scopes, with Auth0's names,
// for the resources zeroauthy stores. Later slices add more.
var ManagementAPIScopes = []store.Scope{
	{Value: "read:clients", Description: "Read applications"},
	{Value: "create:clients", Description: "Create applications"},
	{Value: "update:clients", Description: "Update applications"},
	{Value: "delete:clients", Description: "Delete applications"},
	{Value: "read:client_keys", Description: "Read application secrets and keys"},
	{Value: "create:client_keys", Description: "Create application secrets and keys"},
	{Value: "update:client_keys", Description: "Update application secrets and keys"},
	{Value: "delete:client_keys", Description: "Delete application secrets and keys"},
	{Value: "read:client_grants", Description: "Read application access to APIs"},
	{Value: "create:client_grants", Description: "Grant applications access to APIs"},
	{Value: "update:client_grants", Description: "Update application access to APIs"},
	{Value: "delete:client_grants", Description: "Revoke application access to APIs"},
	{Value: "read:resource_servers", Description: "Read APIs"},
	{Value: "create:resource_servers", Description: "Create APIs"},
	{Value: "update:resource_servers", Description: "Update APIs"},
	{Value: "delete:resource_servers", Description: "Delete APIs"},
	{Value: "read:connections", Description: "Read connections"},
	{Value: "create:connections", Description: "Create connections"},
	{Value: "update:connections", Description: "Update connections"},
	{Value: "delete:connections", Description: "Delete connections"},
	{Value: "read:connections_options", Description: "Read connection options"},
	{Value: "update:connections_options", Description: "Update connection options"},
	{Value: "read:users", Description: "Read users"},
	{Value: "create:users", Description: "Create users"},
	{Value: "update:users", Description: "Update users"},
	{Value: "delete:users", Description: "Delete users"},
	{Value: "read:users_app_metadata", Description: "Read users' app_metadata"},
	{Value: "create:users_app_metadata", Description: "Set users' app_metadata on creation"},
	{Value: "update:users_app_metadata", Description: "Update users' app_metadata"},
	{Value: "create:user_tickets", Description: "Create password-change and email verification tickets"},
	{Value: "read:grants", Description: "Read user consents"},
	{Value: "delete:grants", Description: "Revoke user consents"},
	{Value: "read:refresh_tokens", Description: "Read refresh tokens"},
	{Value: "delete:refresh_tokens", Description: "Revoke refresh tokens"},
	{Value: "read:sessions", Description: "Read sessions"},
	{Value: "delete:sessions", Description: "Revoke sessions"},
	{Value: "read:attack_protection", Description: "Read attack protection"},
	{Value: "update:attack_protection", Description: "Update attack protection"},
	{Value: "read:anomaly_blocks", Description: "Read IP anomaly blocks"},
	{Value: "delete:anomaly_blocks", Description: "Clear IP anomaly blocks"},
	{Value: "read:tenant_settings", Description: "Read tenant settings"},
	{Value: "update:tenant_settings", Description: "Update tenant settings"},
	{Value: "read:email_provider", Description: "Read tenant email provider configuration"},
	{Value: "read:branding", Description: "Read tenant branding and themes"},
	{Value: "update:branding", Description: "Update tenant branding and templates"},
	{Value: "create:branding", Description: "Create tenant branding themes"},
	{Value: "delete:branding", Description: "Delete tenant branding themes"},
	{Value: "read:prompts", Description: "Read Universal Login prompts"},
	{Value: "update:prompts", Description: "Update Universal Login prompts"},
	{Value: "create:email_provider", Description: "Create tenant email provider configuration"},
	{Value: "update:email_provider", Description: "Update tenant email provider configuration"},
	{Value: "delete:email_provider", Description: "Delete tenant email provider configuration"},
	{Value: "read:email_templates", Description: "Read tenant email templates"},
	{Value: "create:email_templates", Description: "Create tenant email templates"},
	{Value: "update:email_templates", Description: "Update tenant email templates"},
	{Value: "read:signing_keys", Description: "Read signing keys"},
	{Value: "create:signing_keys", Description: "Rotate signing keys"},
	{Value: "update:signing_keys", Description: "Revoke signing keys"},
	{Value: "read:rules", Description: "Read retired Rules compatibility collections"},
	{Value: "read:hooks", Description: "Read retired Hooks compatibility collections"},
}

// ManagementAPI creates or repairs the tenant's Management API resource
// server: the canonical identifier (tenant.ManagementAPIIdentifier), the
// scopes above, marked IsSystem. Machine-to-machine clients reach it
// through client grants; tenant users cannot get tokens for it (operators
// use the system tenant's API instead). It returns the stored API. The
// reserved system tenant has none.
func ManagementAPI(ctx context.Context, st store.Store, t *store.Tenant, baseDomain string, now time.Time) (*store.ResourceServer, error) {
	if t.Reserved {
		return nil, errors.New("tenantsetup: the system tenant has no machine-to-machine Management API; only operators manage it")
	}
	id := tenant.ManagementAPIIdentifier(t, baseDomain)
	if id == "" {
		return nil, errors.New("tenantsetup: the tenant has no host, so no Management API identifier")
	}
	err := UpsertResourceServer(ctx, st, t.ID, id, now, func(rs *store.ResourceServer) error {
		rs.Name, rs.SigningAlg, rs.IsSystem = ManagementAPIName, "RS256", true
		rs.Scopes = append([]store.Scope(nil), ManagementAPIScopes...)
		rs.TokenLifetime = 86400
		rs.AllowOfflineAccess = false
		rs.SkipConsentForVerifiableFirstPartyClients = false
		rs.SubjectTypeAuthorization = store.SubjectTypeAuthorization{User: store.PolicyDenyAll, Client: store.PolicyRequireClientGrant}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return st.ResourceServers().GetByIdentifier(ctx, t.ID, id)
}

// UpgradeManagementAPIName updates only the name of an existing ordinary
// tenant system API. It does not create a missing resource or touch settings.
func UpgradeManagementAPIName(ctx context.Context, st store.Store, t *store.Tenant, baseDomain string) error {
	if t == nil || t.Reserved {
		return nil
	}
	identifier := tenant.ManagementAPIIdentifier(t, baseDomain)
	if identifier == "" {
		return nil
	}
	err := st.ResourceServers().RenameSystem(ctx, t.ID, identifier, ManagementAPIName)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// IsManagementAPIScope reports whether s is one of ManagementAPIScopes.
func IsManagementAPIScope(s string) bool {
	for _, d := range ManagementAPIScopes {
		if d.Value == s {
			return true
		}
	}
	return false
}
