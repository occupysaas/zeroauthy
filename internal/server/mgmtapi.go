package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
)

// mgmtAPI adapts mgmt.Handlers to the generated ServerInterface, adding
// each operational route's scope check. The embedded generated Unimplemented
// temporarily returns 501 for future-task routes; each must gain a scoped
// override before it is considered operational. The assertion verifies the
// resulting adapter satisfies the generated interface.
type mgmtAPI struct {
	mgmtapi.Unimplemented
	h *mgmt.Handlers
}

var _ mgmtapi.ServerInterface = mgmtAPI{}

func (a mgmtAPI) GetBranding(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetBranding, "read:branding")
}
func (a mgmtAPI) UpdateBranding(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.UpdateBranding, "update:branding")
}
func (a mgmtAPI) GetUniversalLoginTemplate(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetUniversalLoginTemplate, "read:branding")
}
func (a mgmtAPI) PutUniversalLoginTemplate(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.PutUniversalLoginTemplate, "update:branding")
}
func (a mgmtAPI) DeleteUniversalLoginTemplate(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.DeleteUniversalLoginTemplate, "update:branding")
}
func (a mgmtAPI) CreateBrandingTheme(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateBrandingTheme, "create:branding")
}
func (a mgmtAPI) GetDefaultBrandingTheme(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetDefaultBrandingTheme, "read:branding")
}
func (a mgmtAPI) GetBrandingTheme(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetBrandingTheme(w, r, id) }, "read:branding")
}
func (a mgmtAPI) UpdateBrandingTheme(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateBrandingTheme(w, r, id) }, "update:branding")
}
func (a mgmtAPI) DeleteBrandingTheme(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteBrandingTheme(w, r, id) }, "delete:branding")
}
func (a mgmtAPI) GetPromptSettings(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetPromptSettings, "read:prompts")
}
func (a mgmtAPI) UpdatePromptSettings(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.UpdatePromptSettings, "update:prompts")
}
func (a mgmtAPI) GetPromptCustomText(w http.ResponseWriter, r *http.Request, prompt, language string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetPromptCustomText(w, r, prompt, language) }, "read:prompts")
}
func (a mgmtAPI) PutPromptCustomText(w http.ResponseWriter, r *http.Request, prompt, language string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PutPromptCustomText(w, r, prompt, language) }, "update:prompts")
}
func (a mgmtAPI) GetPromptPartials(w http.ResponseWriter, r *http.Request, prompt string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetPromptPartials(w, r, prompt) }, "read:prompts")
}
func (a mgmtAPI) PutPromptPartials(w http.ResponseWriter, r *http.Request, prompt string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PutPromptPartials(w, r, prompt) }, "update:prompts")
}

// scoped runs fn for a caller holding any of scopes.
func scoped(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc, scopes ...string) {
	mgmt.Require(scopes...)(fn).ServeHTTP(w, r)
}

func (a mgmtAPI) GetClients(w http.ResponseWriter, r *http.Request, p mgmtapi.GetClientsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClients(w, r, p) }, "read:clients")
}

func (a mgmtAPI) CreateClient(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateClient, "create:clients")
}

func (a mgmtAPI) GetClient(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetClientParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClient(w, r, id, p) }, "read:clients")
}

func (a mgmtAPI) ListSigningKeys(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.ListSigningKeys, "read:signing_keys")
}
func (a mgmtAPI) GetSigningKey(w http.ResponseWriter, r *http.Request, kid string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetSigningKey(w, r, kid) }, "read:signing_keys")
}
func (a mgmtAPI) RotateSigningKeys(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.RotateSigningKeys, "create:signing_keys")
}
func (a mgmtAPI) RevokeSigningKey(w http.ResponseWriter, r *http.Request, kid string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RevokeSigningKey(w, r, kid) }, "update:signing_keys")
}
func (a mgmtAPI) GetCustomSigningKeys(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetCustomSigningKeys, "read:signing_keys")
}
func (a mgmtAPI) PutCustomSigningKeys(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.PutCustomSigningKeys, "update:signing_keys")
}
func (a mgmtAPI) DeleteCustomSigningKeys(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.DeleteCustomSigningKeys, "update:signing_keys")
}

func (a mgmtAPI) GetRules(w http.ResponseWriter, r *http.Request, p mgmtapi.GetRulesParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRules(w, r, p) }, "read:rules")
}
func (a mgmtAPI) GetRulesConfigs(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetRulesConfigs, "read:rules")
}
func (a mgmtAPI) GetHooks(w http.ResponseWriter, r *http.Request, p mgmtapi.GetHooksParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetHooks(w, r, p) }, "read:hooks")
}

// UpdateClient: update:clients, or update:client_keys for the secret; the
// handler checks which the body needs.
func (a mgmtAPI) UpdateClient(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateClient(w, r, id) }, "update:clients", "update:client_keys")
}

func (a mgmtAPI) DeleteClient(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteClient(w, r, id) }, "delete:clients")
}

func (a mgmtAPI) RotateClientSecret(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RotateClientSecret(w, r, id) }, "update:client_keys")
}

func (a mgmtAPI) GetResourceServers(w http.ResponseWriter, r *http.Request, p mgmtapi.GetResourceServersParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetResourceServers(w, r, p) }, "read:resource_servers")
}

func (a mgmtAPI) CreateResourceServer(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateResourceServer, "create:resource_servers")
}

func (a mgmtAPI) GetResourceServer(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetResourceServerParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetResourceServer(w, r, id, p) }, "read:resource_servers")
}

func (a mgmtAPI) UpdateResourceServer(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateResourceServer(w, r, id) }, "update:resource_servers")
}

func (a mgmtAPI) DeleteResourceServer(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteResourceServer(w, r, id) }, "delete:resource_servers")
}

func (a mgmtAPI) GetClientGrants(w http.ResponseWriter, r *http.Request, p mgmtapi.GetClientGrantsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClientGrants(w, r, p) }, "read:client_grants")
}

func (a mgmtAPI) CreateClientGrant(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateClientGrant, "create:client_grants")
}

func (a mgmtAPI) GetClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetClientGrant(w, r, id) }, "read:client_grants")
}

func (a mgmtAPI) UpdateClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateClientGrant(w, r, id) }, "update:client_grants")
}

func (a mgmtAPI) DeleteClientGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteClientGrant(w, r, id) }, "delete:client_grants")
}

func (a mgmtAPI) GetConnections(w http.ResponseWriter, r *http.Request, p mgmtapi.GetConnectionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnections(w, r, p) }, "read:connections")
}

func (a mgmtAPI) CreateConnection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateConnection, "create:connections")
}

func (a mgmtAPI) GetConnection(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetConnectionParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnection(w, r, id, p) }, "read:connections")
}

func (a mgmtAPI) UpdateConnection(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateConnection(w, r, id) }, "update:connections")
}

func (a mgmtAPI) DeleteConnection(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteConnection(w, r, id) }, "delete:connections")
}

func (a mgmtAPI) GetConnectionClients(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetConnectionClientsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnectionClients(w, r, id, p) }, "read:connections")
}

func (a mgmtAPI) UpdateConnectionClients(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateConnectionClients(w, r, id) }, "update:connections")
}

func (a mgmtAPI) GetUsers(w http.ResponseWriter, r *http.Request, p mgmtapi.GetUsersParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUsers(w, r, p) }, "read:users")
}

// CreateUser: create:users; app_metadata in the body also needs
// create:users_app_metadata or update:users_app_metadata, which the
// handler checks.
func (a mgmtAPI) CreateUser(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateUser, "create:users")
}

func (a mgmtAPI) GetUsersByEmail(w http.ResponseWriter, r *http.Request, p mgmtapi.GetUsersByEmailParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUsersByEmail(w, r, p) }, "read:users")
}

func (a mgmtAPI) GetUser(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetUserParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUser(w, r, id, p) }, "read:users")
}

// UpdateUser: update:users, or update:users_app_metadata for app_metadata;
// the handler checks which the body needs.
func (a mgmtAPI) UpdateUser(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateUser(w, r, id) }, "update:users", "update:users_app_metadata")
}

func (a mgmtAPI) DeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUser(w, r, id) }, "delete:users")
}

// LinkUserIdentity: update:users.
func (a mgmtAPI) LinkUserIdentity(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.LinkUserIdentity(w, r, id) }, "update:users")
}

// UnlinkUserIdentity: update:users.
func (a mgmtAPI) UnlinkUserIdentity(w http.ResponseWriter, r *http.Request, id, provider, userID string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UnlinkUserIdentity(w, r, id, provider, userID) }, "update:users")
}

// CreatePasswordChangeTicket: create:user_tickets.
func (a mgmtAPI) CreatePasswordChangeTicket(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreatePasswordChangeTicket, "create:user_tickets")
}

// CreateEmailVerificationTicket: create:user_tickets.
func (a mgmtAPI) CreateEmailVerificationTicket(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateEmailVerificationTicket, "create:user_tickets")
}

// The system API: the router lets only operators reach it (operatorOnly).

func (a mgmtAPI) GetTenants(w http.ResponseWriter, r *http.Request)   { a.h.GetTenants(w, r) }
func (a mgmtAPI) CreateTenant(w http.ResponseWriter, r *http.Request) { a.h.CreateTenant(w, r) }

func (a mgmtAPI) UpdateTenant(w http.ResponseWriter, r *http.Request, name string) {
	a.h.UpdateTenant(w, r, name)
}

func (a mgmtAPI) DeleteTenant(w http.ResponseWriter, r *http.Request, name string, p mgmtapi.DeleteTenantParams) {
	a.h.DeleteTenant(w, r, name, p)
}

func (a mgmtAPI) GetOperators(w http.ResponseWriter, r *http.Request)   { a.h.GetOperators(w, r) }
func (a mgmtAPI) CreateOperator(w http.ResponseWriter, r *http.Request) { a.h.CreateOperator(w, r) }

func (a mgmtAPI) UpdateOperator(w http.ResponseWriter, r *http.Request, id string) {
	a.h.UpdateOperator(w, r, id)
}
func (a mgmtAPI) GetConsoleTenants(w http.ResponseWriter, r *http.Request) {
	a.h.GetConsoleTenants(w, r)
}

func (a mgmtAPI) DeleteOperator(w http.ResponseWriter, r *http.Request, id string) {
	a.h.DeleteOperator(w, r, id)
}

func (a mgmtAPI) GetTenantJobs(w http.ResponseWriter, r *http.Request, tenant string, p mgmtapi.GetTenantJobsParams) {
	a.h.GetTenantJobs(w, r, tenant, p)
}

func (a mgmtAPI) TryConnectionScript(w http.ResponseWriter, r *http.Request, tenant, id, name string) {
	a.h.TryConnectionScript(w, r, tenant, id, name)
}

func (a mgmtAPI) PreviewTenantEmail(w http.ResponseWriter, r *http.Request, tenant string) {
	a.h.PreviewEmail(w, r, tenant)
}

func (a mgmtAPI) TestTenantEmail(w http.ResponseWriter, r *http.Request, tenant string) {
	a.h.TestEmail(w, r, tenant)
}

// GetUserSessions: read:sessions.
func (a mgmtAPI) GetUserSessions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserSessionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUserSessions(w, r, id) }, "read:sessions")
}

// DeleteUserSessions: delete:sessions.
func (a mgmtAPI) DeleteUserSessions(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUserSessions(w, r, id) }, "delete:sessions")
}

// GetUserRefreshTokens: read:refresh_tokens.
func (a mgmtAPI) GetUserRefreshTokens(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserRefreshTokensParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUserRefreshTokens(w, r, id) }, "read:refresh_tokens")
}

// DeleteUserRefreshTokens: delete:refresh_tokens.
func (a mgmtAPI) DeleteUserRefreshTokens(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUserRefreshTokens(w, r, id) }, "delete:refresh_tokens")
}

// GetSession: read:sessions.
func (a mgmtAPI) GetSession(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetSession(w, r, id) }, "read:sessions")
}

// DeleteSession: delete:sessions.
func (a mgmtAPI) DeleteSession(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteSession(w, r, id) }, "delete:sessions")
}

// GetRefreshToken: read:refresh_tokens.
func (a mgmtAPI) GetRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRefreshToken(w, r, id) }, "read:refresh_tokens")
}

// DeleteRefreshToken: delete:refresh_tokens.
func (a mgmtAPI) DeleteRefreshToken(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteRefreshToken(w, r, id) }, "delete:refresh_tokens")
}

// GetGrants: read:grants.
func (a mgmtAPI) GetGrants(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetGrantsParams) {
	scoped(w, r, a.h.GetGrants, "read:grants")
}

// DeleteGrantsByUser: delete:grants.
func (a mgmtAPI) DeleteGrantsByUser(w http.ResponseWriter, r *http.Request, _ mgmtapi.DeleteGrantsByUserParams) {
	scoped(w, r, a.h.DeleteGrantsByUser, "delete:grants")
}

// DeleteGrant: delete:grants.
func (a mgmtAPI) DeleteGrant(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteGrant(w, r, id) }, "delete:grants")
}

// GetJob: create:users or read:users.
func (a mgmtAPI) GetJob(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetJob(w, r, id) }, "create:users", "read:users")
}

// GetJobErrors: create:users or read:users.
func (a mgmtAPI) GetJobErrors(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetJobErrors(w, r, id) }, "create:users", "read:users")
}

// CreateUsersImportJob: create:users.
func (a mgmtAPI) CreateUsersImportJob(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateUsersImportJob, "create:users")
}

// CreateUsersExportJob: read:users.
func (a mgmtAPI) CreateUsersExportJob(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateUsersExportJob, "read:users")
}

// CreateVerificationEmailJob: update:users.
func (a mgmtAPI) CreateVerificationEmailJob(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateVerificationEmailJob, "update:users")
}

func (a mgmtAPI) GetTenantSettings(w http.ResponseWriter, r *http.Request, p mgmtapi.GetTenantSettingsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetTenantSettings(w, r, p) }, "read:tenant_settings")
}
func (a mgmtAPI) UpdateTenantSettings(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.UpdateTenantSettings, "update:tenant_settings")
}

func (a mgmtAPI) GetEmailProvider(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetEmailProvider, "read:email_provider")
}
func (a mgmtAPI) CreateEmailProvider(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateEmailProvider, "create:email_provider")
}
func (a mgmtAPI) PatchEmailProvider(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.PatchEmailProvider, "update:email_provider")
}
func (a mgmtAPI) DeleteEmailProvider(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.DeleteEmailProvider, "delete:email_provider")
}
func (a mgmtAPI) CreateEmailTemplate(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateEmailTemplate, "create:email_templates")
}
func (a mgmtAPI) GetEmailTemplate(w http.ResponseWriter, r *http.Request, name string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetEmailTemplate(w, r, name) }, "read:email_templates")
}
func (a mgmtAPI) PutEmailTemplate(w http.ResponseWriter, r *http.Request, name string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PutEmailTemplate(w, r, name) }, "update:email_templates")
}
func (a mgmtAPI) PatchEmailTemplate(w http.ResponseWriter, r *http.Request, name string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PatchEmailTemplate(w, r, name) }, "update:email_templates")
}

func (a mgmtAPI) GetBruteForceProtection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetProtection(w, r, "brute-force-protection") }, "read:attack_protection")
}

func (a mgmtAPI) UpdateBruteForceProtection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateProtection(w, r, "brute-force-protection") }, "update:attack_protection")
}

func (a mgmtAPI) GetSuspiciousIpThrottling(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetProtection(w, r, "suspicious-ip-throttling") }, "read:attack_protection")
}

func (a mgmtAPI) UpdateSuspiciousIpThrottling(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateProtection(w, r, "suspicious-ip-throttling") }, "update:attack_protection")
}

func (a mgmtAPI) GetBreachedPasswordDetection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetProtection(w, r, "breached-password-detection") }, "read:attack_protection")
}

func (a mgmtAPI) UpdateBreachedPasswordDetection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.UpdateProtection(w, r, "breached-password-detection")
	}, "update:attack_protection")
}

func (a mgmtAPI) GetBotDetection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetProtection(w, r, "bot-detection") }, "read:attack_protection")
}

func (a mgmtAPI) UpdateBotDetection(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateProtection(w, r, "bot-detection") }, "update:attack_protection")
}

func (a mgmtAPI) GetCaptcha(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetProtection(w, r, "captcha") }, "read:attack_protection")
}

func (a mgmtAPI) UpdateCaptcha(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateProtection(w, r, "captcha") }, "update:attack_protection")
}

func (a mgmtAPI) GetUserBlocksByIdentifier(w http.ResponseWriter, r *http.Request, p mgmtapi.GetUserBlocksByIdentifierParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UserBlocks(w, r, "") }, "read:users")
}
func (a mgmtAPI) DeleteUserBlocksByIdentifier(w http.ResponseWriter, r *http.Request, p mgmtapi.DeleteUserBlocksByIdentifierParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UserBlocks(w, r, "") }, "update:users")
}
func (a mgmtAPI) GetUserBlocks(w http.ResponseWriter, r *http.Request, id string, p mgmtapi.GetUserBlocksParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UserBlocks(w, r, id) }, "read:users")
}
func (a mgmtAPI) DeleteUserBlocks(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UserBlocks(w, r, id) }, "update:users")
}
func (a mgmtAPI) GetIPBlock(w http.ResponseWriter, r *http.Request, ip string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.IPBlock(w, r, ip) }, "read:anomaly_blocks")
}
func (a mgmtAPI) DeleteIPBlock(w http.ResponseWriter, r *http.Request, ip string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.IPBlock(w, r, ip) }, "delete:anomaly_blocks")
}

func (a mgmtAPI) PreviewTenantBranding(w http.ResponseWriter, r *http.Request, tenant string) {
	a.h.PreviewBranding(w, r, tenant)
}

// GetCustomDomains: read:custom_domains.
func (a mgmtAPI) GetCustomDomains(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetCustomDomainsParams) {
	scoped(w, r, a.h.GetCustomDomains, "read:custom_domains")
}

// CreateCustomDomain: create:custom_domains.
func (a mgmtAPI) CreateCustomDomain(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateCustomDomain, "create:custom_domains")
}

// GetDefaultCustomDomain: read:custom_domains.
func (a mgmtAPI) GetDefaultCustomDomain(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.GetDefaultCustomDomain, "read:custom_domains")
}

// SetDefaultCustomDomain: update:custom_domains.
func (a mgmtAPI) SetDefaultCustomDomain(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.SetDefaultCustomDomain, "update:custom_domains")
}

// GetCustomDomain: read:custom_domains.
func (a mgmtAPI) GetCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetCustomDomain(w, r, id) }, "read:custom_domains")
}

// UpdateCustomDomain: update:custom_domains.
func (a mgmtAPI) UpdateCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateCustomDomain(w, r, id) }, "update:custom_domains")
}

// DeleteCustomDomain: delete:custom_domains.
func (a mgmtAPI) DeleteCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteCustomDomain(w, r, id) }, "delete:custom_domains")
}

// VerifyCustomDomain: update:custom_domains.
func (a mgmtAPI) VerifyCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.VerifyCustomDomain(w, r, id) }, "update:custom_domains")
}

// TestCustomDomain: update:custom_domains.
func (a mgmtAPI) TestCustomDomain(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.TestCustomDomain(w, r, id) }, "update:custom_domains")
}

func (a mgmtAPI) GetRoles(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetRolesParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRoles(w, r) }, "read:roles")
}

func (a mgmtAPI) PostRoles(w http.ResponseWriter, r *http.Request) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PostRoles(w, r) }, "create:roles")
}

func (a mgmtAPI) GetRolesById(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRolesById(w, r, id) }, "read:roles")
}

func (a mgmtAPI) PatchRolesById(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PatchRolesById(w, r, id) }, "update:roles")
}

func (a mgmtAPI) DeleteRolesById(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteRolesById(w, r, id) }, "delete:roles")
}

func (a mgmtAPI) GetRolePermissions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetRolePermissionsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRolePermissions(w, r, id) }, "read:roles")
}

func (a mgmtAPI) PostRolePermissions(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PostRolePermissions(w, r, id) }, "update:roles")
}

func (a mgmtAPI) DeleteRolePermissions(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteRolePermissions(w, r, id) }, "update:roles")
}

func (a mgmtAPI) GetRoleUsers(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetRoleUsersParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetRoleUsers(w, r, id) }, "read:users", "read:roles", "read:role_members")
}

func (a mgmtAPI) PostRoleUsers(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PostRoleUsers(w, r, id) }, "update:roles", "create:role_members")
}

func (a mgmtAPI) GetUserRoles(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserRolesParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUserRoles(w, r, id) }, "read:users", "read:roles", "read:role_members")
}

func (a mgmtAPI) PostUserRoles(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PostUserRoles(w, r, id) }, "update:users", "create:role_members")
}

func (a mgmtAPI) DeleteUserRoles(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUserRoles(w, r, id) }, "update:users", "delete:role_members")
}

func (a mgmtAPI) GetUserPermissions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetUserPermissionsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetUserPermissions(w, r, id) }, "read:users")
}

func (a mgmtAPI) PostUserPermissions(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PostUserPermissions(w, r, id) }, "update:users")
}

func (a mgmtAPI) DeleteUserPermissions(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteUserPermissions(w, r, id) }, "update:users")
}

// scopedAll requires every documented scope; membership APIs combine user and role privileges.
func scopedAll(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc, scopes ...string) {
	for _, scope := range scopes {
		caller, ok := mgmt.CallerFrom(r.Context())
		if !ok {
			mgmt.WriteError(w, 401, "invalid_token", "Missing authentication")
			return
		}
		if !caller.Has(scope) {
			mgmt.WriteError(w, 403, "insufficient_scope", "Insufficient scope")
			return
		}
	}
	fn(w, r)
}

func (a mgmtAPI) GetActions(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetActionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActions(w, r) }, "read:actions")
}

func (a mgmtAPI) CreateAction(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateAction(w, r) }, "create:actions")
}

func (a mgmtAPI) GetAction(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetAction(w, r, id) }, "read:actions")
}

func (a mgmtAPI) UpdateAction(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateAction(w, r, id) }, "update:actions")
}

func (a mgmtAPI) DeleteAction(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.DeleteActionParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteAction(w, r, id) }, "delete:actions")
}

func (a mgmtAPI) DeployAction(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeployAction(w, r, id) }, "create:actions")
}

func (a mgmtAPI) GetActionVersions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetActionVersionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionVersions(w, r, id) }, "read:actions")
}

func (a mgmtAPI) GetActionVersion(w http.ResponseWriter, r *http.Request, id string, versionId string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionVersion(w, r, id, versionId) }, "read:actions")
}

func (a mgmtAPI) DeployActionVersion(w http.ResponseWriter, r *http.Request, id string, versionId string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeployActionVersion(w, r, id, versionId) }, "create:actions")
}

func (a mgmtAPI) TestAction(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.TestAction(w, r, id) }, "create:actions")
}

func (a mgmtAPI) GetActionTriggers(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionTriggers(w, r) }, "read:actions")
}

func (a mgmtAPI) GetActionBindings(w http.ResponseWriter, r *http.Request, triggerId string, _ mgmtapi.GetActionBindingsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionBindings(w, r, triggerId) }, "read:actions")
}

func (a mgmtAPI) UpdateActionBindings(w http.ResponseWriter, r *http.Request, triggerId string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateActionBindings(w, r, triggerId) }, "update:actions")
}

func (a mgmtAPI) GetActionExecution(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionExecution(w, r, id) }, "read:actions")
}

func (a mgmtAPI) GetActionModules(w http.ResponseWriter, r *http.Request, _ mgmtapi.GetActionModulesParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionModules(w, r) }, "read:actions")
}

func (a mgmtAPI) CreateActionModule(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateActionModule(w, r) }, "create:actions")
}

func (a mgmtAPI) GetActionModule(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionModule(w, r, id) }, "read:actions")
}

func (a mgmtAPI) UpdateActionModule(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateActionModule(w, r, id) }, "update:actions")
}

func (a mgmtAPI) DeleteActionModule(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteActionModule(w, r, id) }, "delete:actions")
}

func (a mgmtAPI) GetActionModuleActions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetActionModuleActionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionModuleActions(w, r, id) }, "read:actions")
}

func (a mgmtAPI) RollbackActionModule(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RollbackActionModule(w, r, id) }, "update:actions")
}

func (a mgmtAPI) GetActionModuleVersions(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.GetActionModuleVersionsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionModuleVersions(w, r, id) }, "read:actions")
}

func (a mgmtAPI) PublishActionModule(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.PublishActionModule(w, r, id) }, "update:actions")
}

func (a mgmtAPI) GetActionModuleVersion(w http.ResponseWriter, r *http.Request, id string, versionId string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetActionModuleVersion(w, r, id, versionId) }, "read:actions")
}

func (a mgmtAPI) GetTenantActionExecutionAttempt(w http.ResponseWriter, r *http.Request, tenant string, id string) {
	a.h.GetTenantActionExecutionAttempt(w, r, tenant, id)
}

// Organizations (Plan 29, D-0055). POST /organizations also needs
// create:organization_connections for enabled_connections; the handler
// checks it.
func (a mgmtAPI) ListOrganizations(w http.ResponseWriter, r *http.Request, _ mgmtapi.ListOrganizationsParams) {
	scopedAll(w, r, a.h.ListOrganizations, "read:organizations")
}
func (a mgmtAPI) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	scopedAll(w, r, a.h.CreateOrganization, "create:organizations")
}
func (a mgmtAPI) GetOrganizationByName(w http.ResponseWriter, r *http.Request, name string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetOrganizationByName(w, r, name) }, "read:organizations")
}
func (a mgmtAPI) GetOrganization(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetOrganization(w, r, id) }, "read:organizations")
}
func (a mgmtAPI) UpdateOrganization(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateOrganization(w, r, id) }, "update:organizations")
}
func (a mgmtAPI) DeleteOrganization(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteOrganization(w, r, id) }, "delete:organizations")
}
func (a mgmtAPI) ListOrganizationConnections(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListOrganizationConnectionsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationConnections(w, r, id) }, "read:organization_connections")
}
func (a mgmtAPI) CreateOrganizationConnection(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateOrganizationConnection(w, r, id) }, "create:organization_connections")
}
func (a mgmtAPI) GetOrganizationConnection(w http.ResponseWriter, r *http.Request, id, connectionId string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetOrganizationConnection(w, r, id, connectionId) }, "read:organization_connections")
}
func (a mgmtAPI) UpdateOrganizationConnection(w http.ResponseWriter, r *http.Request, id, connectionId string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateOrganizationConnection(w, r, id, connectionId) }, "update:organization_connections")
}
func (a mgmtAPI) DeleteOrganizationConnection(w http.ResponseWriter, r *http.Request, id, connectionId string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteOrganizationConnection(w, r, id, connectionId) }, "delete:organization_connections")
}
func (a mgmtAPI) ListOrganizationAllConnections(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListOrganizationAllConnectionsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationAllConnections(w, r, id) }, "read:organization_connections")
}
func (a mgmtAPI) CreateOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateOrganizationAllConnection(w, r, id) }, "create:organization_connections")
}
func (a mgmtAPI) GetOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id, connectionId string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetOrganizationAllConnection(w, r, id, connectionId) }, "read:organization_connections")
}
func (a mgmtAPI) UpdateOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id, connectionId string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.UpdateOrganizationAllConnection(w, r, id, connectionId)
	}, "update:organization_connections")
}
func (a mgmtAPI) DeleteOrganizationAllConnection(w http.ResponseWriter, r *http.Request, id, connectionId string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.DeleteOrganizationAllConnection(w, r, id, connectionId)
	}, "delete:organization_connections")
}
func (a mgmtAPI) ListOrganizationClientGrants(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListOrganizationClientGrantsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationClientGrants(w, r, id) }, "read:organization_client_grants")
}

// Organization members and roles (Plan 29, D-0055). The member list and the
// user organizations accept any of their scopes; role members need both.
// fields=roles on the member list also needs read:organization_member_roles;
// the handler checks it.
func (a mgmtAPI) ListOrganizationMembers(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListOrganizationMembersParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationMembers(w, r, id) }, "read:organization_members", "read:organization_member_roles")
}
func (a mgmtAPI) AddOrganizationMembers(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AddOrganizationMembers(w, r, id) }, "create:organization_members")
}
func (a mgmtAPI) RemoveOrganizationMembers(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RemoveOrganizationMembers(w, r, id) }, "delete:organization_members")
}
func (a mgmtAPI) ListOrganizationMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string, _ mgmtapi.ListOrganizationMemberRolesParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationMemberRoles(w, r, id, userID) }, "read:organization_member_roles")
}
func (a mgmtAPI) AddOrganizationMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AddOrganizationMemberRoles(w, r, id, userID) }, "create:organization_member_roles")
}
func (a mgmtAPI) RemoveOrganizationMemberRoles(w http.ResponseWriter, r *http.Request, id, userID string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RemoveOrganizationMemberRoles(w, r, id, userID) }, "delete:organization_member_roles")
}
func (a mgmtAPI) ListOrganizationMemberEffectiveRoles(w http.ResponseWriter, r *http.Request, id, userID string, _ mgmtapi.ListOrganizationMemberEffectiveRolesParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.ListOrganizationMemberEffectiveRoles(w, r, id, userID)
	}, "read:organization_member_effective_roles")
}
func (a mgmtAPI) ListOrganizationRoleMembers(w http.ResponseWriter, r *http.Request, id, roleID string, _ mgmtapi.ListOrganizationRoleMembersParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationRoleMembers(w, r, id, roleID) }, "read:organization_members", "read:roles")
}
func (a mgmtAPI) ListUserOrganizations(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListUserOrganizationsParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListUserOrganizations(w, r, id) }, "read:users", "read:organizations")
}

func (a mgmtAPI) CreateOrganizationInvitation(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.CreateOrganizationInvitationParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateOrganizationInvitation(w, r, id) }, "create:organization_invitations")
}
func (a mgmtAPI) ListOrganizationInvitations(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListOrganizationInvitationsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationInvitations(w, r, id) }, "read:organization_invitations")
}
func (a mgmtAPI) GetOrganizationInvitation(w http.ResponseWriter, r *http.Request, id, invitationID string, _ mgmtapi.GetOrganizationInvitationParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetOrganizationInvitation(w, r, id, invitationID) }, "read:organization_invitations")
}
func (a mgmtAPI) DeleteOrganizationInvitation(w http.ResponseWriter, r *http.Request, id, invitationID string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteOrganizationInvitation(w, r, id, invitationID) }, "delete:organization_invitations")
}

func (a mgmtAPI) ListOrganizationClients(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.ListOrganizationClientsParams) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.ListOrganizationClients(w, r, id) }, "read:organization_clients")
}
func (a mgmtAPI) AssociateOrganizationClients(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.AssociateOrganizationClients(w, r, id) }, "create:organization_clients")
}
func (a mgmtAPI) DeleteOrganizationClients(w http.ResponseWriter, r *http.Request, id string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteOrganizationClients(w, r, id) }, "delete:organization_clients")
}
func (a mgmtAPI) GetOrganizationClient(w http.ResponseWriter, r *http.Request, id, clientID string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetOrganizationClient(w, r, id, clientID) }, "read:organization_clients")
}
func (a mgmtAPI) UpdateOrganizationClient(w http.ResponseWriter, r *http.Request, id, clientID string) {
	scopedAll(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateOrganizationClient(w, r, id, clientID) }, "update:organization_clients")
}
