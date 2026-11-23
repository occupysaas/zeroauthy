import type { components } from './schema'
import type { Role, RolePage, PermissionKey, PermissionPage, RoleUserPage, OffsetPage } from './rbac'
export type { Role, RolePage, PermissionKey, Permission, PermissionSource, PermissionPage, RoleUser, RoleUserPage } from './rbac'
import type { Group, GroupPage, GroupCheckpoint, GroupMemberPage, GroupRolePage, UserGroupPage, ScimConfiguration, ScimMappingItem, ScimToken, ScimTokenCreate, ScimTokenCreated, SelfServiceProfile, SelfServiceProfileCreate, SelfServiceProfileUpdate, SsoTicketRequest, ConnectionProfile, ConnectionProfileCreate, DirectoryProvisioning, DirectoryProvisioningUpdate, DirectoryMappingItem, SynchronizedGroup } from './directory'
export type { Group, GroupPage, GroupCheckpoint, GroupMember, GroupMemberPage, GroupRolePage, UserGroup, UserGroupPage, ScimConfiguration, ScimMappingItem, ScimToken, ScimTokenCreate, ScimTokenCreated, SelfServiceProfile, SelfServiceProfileCreate, SelfServiceProfileUpdate, SsoTicketRequest, ConnectionProfile, ConnectionProfileCreate } from './directory'

// A thin, typed wrapper over fetch for the Management and system APIs.

export type EventStream = components['schemas']['EventsEventStreamResponseContent']
export type EventStreamCreate = components['schemas']['EventsCreateEventStreamWebHookRequestContent'] | components['schemas']['EventsCreateEventStreamActionRequestContent'] | components['schemas']['EventsCreateEventStreamEventBridgeRequestContent']
export type EventStreamPatch = components['schemas']['EventsUpdateEventStreamRequestContent']
export type EventType = components['schemas']['EventsEventStreamEventTypeEnum']
export type EventDelivery = components['schemas']['EventsEventStreamDelivery']
export type EventTestRequest = components['schemas']['EventsCreateEventStreamTestEventRequestContent']
export type EventTestResult = components['schemas']['EventsCreateEventStreamTestEventResponseContent']
export type EventRedelivery = components['schemas']['EventsCreateEventStreamRedeliveryRequestContent']
export type EventDeliveryQuery = { statuses?: string; event_types?: string; date_from?: string; date_to?: string; from?: string; take: number }

export type Client = components['schemas']['Client']
export type ClientCreate = components['schemas']['ClientCreate']
export type ClientUpdate = components['schemas']['ClientUpdate']
export type ClientPage = components['schemas']['ClientPage']
export type AppType = components['schemas']['AppType']
export type ConsoleAuthenticationMethod = components['schemas']['ConsoleAuthenticationMethod']
export type ConsoleRelyingPartyId = components['schemas']['ConsoleRelyingPartyId']
export type ClientCredential = components['schemas']['ClientCredential']
export type ClientCredentialCreate = components['schemas']['ClientCredentialCreate']
export type ClientCredentialUpdate = components['schemas']['ClientCredentialUpdate']
export type TokenExchangeProfile = components['schemas']['TokenExchangeProfile']
export type TokenExchangeProfileCreate = components['schemas']['TokenExchangeProfileCreate']
export type TokenExchangeProfileUpdate = components['schemas']['TokenExchangeProfileUpdate']
export type TokenExchangeProfilePage = components['schemas']['TokenExchangeProfilePage']
export type SystemTenant = components['schemas']['SystemTenant']
export type TenantCreate = components['schemas']['TenantCreate']
export type ResourceServer = components['schemas']['ResourceServer']
export type ResourceServerCreate = components['schemas']['ResourceServerCreate']
export type ResourceServerUpdate = components['schemas']['ResourceServerUpdate']
export type ResourceServerPage = components['schemas']['ResourceServerPage']
export type ResourceServerScope = components['schemas']['ResourceServerScope']
export type ClientGrant = components['schemas']['ClientGrant']
export type ClientGrantCreate = components['schemas']['ClientGrantCreate']
export type ClientGrantUpdate = components['schemas']['ClientGrantUpdate']
export type ClientGrantPage = components['schemas']['ClientGrantPage']
export type Operator = components['schemas']['Operator']
export type OperatorInvite = components['schemas']['OperatorInvite']
export type Connection = components['schemas']['Connection']
export type ConnectionKey = components['schemas']['ConnectionKey']
export type ConnectionCreate = components['schemas']['ConnectionCreate']
export type ConnectionUpdate = components['schemas']['ConnectionUpdate']
export type ConnectionPage = components['schemas']['ConnectionPage']
export type ConnectionClientStatus = components['schemas']['ConnectionClientStatus']
export type ScriptTryResult = components['schemas']['ScriptTryResult']
export type User = components['schemas']['User']
export type UserCreate = components['schemas']['UserCreate']
export type UserPage = components['schemas']['UserPage']
export type UserUpdate = components['schemas']['UserProfileSettings']
export type UserIdentity = components['schemas']['UserIdentity']
export type UserSession = components['schemas']['UserSession']
export type UserSessionPage = components['schemas']['UserSessionPage']
// openapi-typescript renders the required-only allOf branch as Record<string, never>.
// Keep the wire schema's required properties while deriving their types from the generated base.
type RefreshTokenView = components['schemas']['RefreshToken']
export type UserRefreshToken = RefreshTokenView & Required<Pick<RefreshTokenView, 'id' | 'user_id' | 'created_at' | 'idle_expires_at' | 'expires_at' | 'client_id' | 'session_id' | 'rotating' | 'resource_servers' | 'last_exchanged_at'>>
export type UserRefreshTokenPage = Omit<components['schemas']['UserRefreshTokenPage'], 'tokens'> & { tokens: UserRefreshToken[] }
export type UserGrant = components['schemas']['UserGrant']
export type Job = components['schemas']['Job']
export type JobPage = components['schemas']['JobPage']
export type JobError = components['schemas']['JobError']
export type UsersExportJobCreate = components['schemas']['UsersExportJobCreate']
export type ManagementError = components['schemas']['ManagementError']
export type ManagedSigningKey = components['schemas']['ManagedSigningKey']
export type CustomSigningJWKS = components['schemas']['CustomSigningJWKS']
export type EmailProvider = components['schemas']['EmailProvider']
export type EmailProviderWrite = components['schemas']['EmailProviderWrite']
export type EmailTemplate = components['schemas']['EmailTemplate']
export type EmailTemplatePatch = components['schemas']['EmailTemplatePatch']
export type EmailPreview = components['schemas']['EmailPreview']
export type EmailTemplateName =
  | 'verify_email' | 'verify_email_by_code' | 'auth_email_by_code' | 'reset_email' | 'reset_email_by_code'
  | 'welcome_email' | 'blocked_account' | 'stolen_credentials' | 'enrollment_email' | 'mfa_oob_code'
  | 'user_invitation' | 'async_approval' | 'change_password' | 'password_reset'

export type TenantSettings = components['schemas']['TenantSettings']
export type TenantSettingsPatch = components['schemas']['TenantSettingsPatch']
export type BruteForceProtection = components['schemas']['BruteForceProtection']
export type BruteForceProtectionUpdate = components['schemas']['BruteForceProtectionUpdate']
export type SuspiciousIpThrottling = components['schemas']['SuspiciousIpThrottling']
export type SuspiciousIpThrottlingUpdate = components['schemas']['SuspiciousIpThrottlingUpdate']
export type BreachedPasswordDetection = components['schemas']['BreachedPasswordDetection']
export type BreachedPasswordDetectionUpdate = components['schemas']['BreachedPasswordDetectionUpdate']
export type BotDetection = components['schemas']['BotDetection']
export type BotDetectionUpdate = components['schemas']['BotDetectionUpdate']
export type Captcha = components['schemas']['Captcha']
export type CaptchaUpdate = components['schemas']['CaptchaUpdate']
export type UserBlocks = components['schemas']['UserBlocks']
export type CustomDomain = components['schemas']['CustomDomain']
export type CustomDomainVerified = components['schemas']['CustomDomainVerified']
export type CustomDomainCreate = components['schemas']['CustomDomainCreate']
export type CustomDomainUpdate = components['schemas']['CustomDomainUpdate']
export type CustomDomainTest = components['schemas']['CustomDomainTest']

export type ActionModule = components['schemas']['ActionModule']
export type ActionModuleVersion = components['schemas']['ActionModuleVersion']
export type ActionModuleRef = components['schemas']['ActionModuleRef']
export type ActionModuleCreate = components['schemas']['ActionModuleCreate']
export type ActionModuleUpdate = components['schemas']['ActionModuleUpdate']
export type ActionModulesPage = components['schemas']['ActionModulesPage']
export type ActionModuleVersionsPage = components['schemas']['ActionModuleVersionsPage']
export type ActionModuleActionsPage = components['schemas']['ActionModuleActionsPage']
export type Action = components['schemas']['Action']
export type ActionCreate = components['schemas']['ActionCreate']
export type ActionUpdate = components['schemas']['ActionUpdate']
export type ActionVersion = components['schemas']['ActionVersion']
export type ActionTrigger = components['schemas']['ActionTrigger']
export type ActionDependency = components['schemas']['ActionDependency']
export type ActionSecretInput = components['schemas']['ActionSecretInput']
export type ActionBinding = components['schemas']['ActionBinding']
export type ActionBindingInput = components['schemas']['ActionBindingInput']
export type ActionsPage = components['schemas']['ActionsPage']
export type ActionVersionsPage = components['schemas']['ActionVersionsPage']
export type ActionBindingsPage = components['schemas']['ActionBindingsPage']
export type ActionBindings = components['schemas']['ActionBindings']
export type ActionBindingsUpdate = components['schemas']['ActionBindingsUpdate']
export type ActionTriggers = components['schemas']['ActionTriggers']
export type ActionTestRequest = components['schemas']['ActionTestRequest']
export type ActionTestResponse = components['schemas']['ActionTestResponse']
export type ActionExecution = components['schemas']['ActionExecution']

export type LogEvent = components['schemas']['LogEvent']
export type LogItem = components['schemas']['LogEventListItem']
export type LogPage = components['schemas']['LogEventsPage']
export type LogStream = components['schemas']['LogStream']
export type LogStreamCreate = components['schemas']['LogStreamCreate']
export type LogStreamPatch = components['schemas']['LogStreamPatch']
export type LogStat = components['schemas']['LogDailyStat']
export type StreamStatus = components['schemas']['SystemLogStreamStatus']
export type SystemExecution = components['schemas']['SystemActionExecution']

export type Organization = components['schemas']['Organization']
export type OrganizationCreate = components['schemas']['OrganizationCreate']
export type OrganizationUpdate = components['schemas']['OrganizationUpdate']
export type OrganizationsPage = components['schemas']['OrganizationsPage']
export type OrganizationEnabledConnection = components['schemas']['OrganizationEnabledConnection']
export type OrganizationEnabledConnectionCreate = components['schemas']['OrganizationEnabledConnectionCreate']
export type OrganizationEnabledConnectionUpdate = components['schemas']['OrganizationEnabledConnectionUpdate']
export type OrganizationEnabledConnectionsPage = components['schemas']['OrganizationEnabledConnectionsPage']
export type OrganizationMember = components['schemas']['OrganizationMember']
export type OrganizationMembersPage = components['schemas']['OrganizationMembersPage']

export type OrganizationInvitation = components['schemas']['OrganizationInvitation']
export type OrganizationInvitationCreate = components['schemas']['OrganizationInvitationCreate']
export type OrganizationClientAssociation = components['schemas']['OrganizationClientAssociation']
export type OrganizationDiscoveryDomain = components['schemas']['OrganizationDiscoveryDomain']
export type OrganizationConnection = components['schemas']['OrganizationConnection']
export type OrganizationConnectionUpdate = components['schemas']['OrganizationConnectionUpdate']
export type OrganizationClientGrant = components['schemas']['OrganizationClientGrant']

export type GuardianFactors = components['schemas']['MFAGetGuardianFactorsResponse']
export type GuardianPolicies = components['schemas']['MFASetGuardianPoliciesRequest']
export type AuthenticationMethods = components['schemas']['MFAGetAuthenticationMethodsResponse']
export type AuthenticationMethod = Extract<AuthenticationMethods, unknown[]>[number]
export type GuardianConfiguration = components['schemas']['MFASetGuardianFactorsSmsProvidersTwilioRequest']
  | components['schemas']['MFASetGuardianFactorsSmsTemplatesRequest']
  | components['schemas']['MFASetGuardianFactorsSmsSelectedProviderRequest']
  | components['schemas']['MFASetGuardianFactorsPhoneSettingsRequest']
  | components['schemas']['MFASetGuardianFactorsPhoneMessageTypesRequest']
  | components['schemas']['MFASetGuardianFactorsPushNotificationProvidersApnsRequest']
  | components['schemas']['MFASetGuardianFactorsPushNotificationProvidersFcmRequest']
  | components['schemas']['MFASetGuardianFactorsPushNotificationProvidersFcmv1Request']
  | components['schemas']['MFASetGuardianFactorsPushNotificationProvidersSnsRequest']
  | components['schemas']['MFASetGuardianFactorsPushNotificationSelectedProviderRequest']
  | components['schemas']['MFASetGuardianFactorsDuoSettingsRequest']
export type GuardianConfigurationRoute = 'sms/templates' | 'phone/templates' | 'sms/providers/twilio' | 'phone/providers/twilio'
  | 'sms/selected-provider' | 'phone/selected-provider' | 'phone/message-types' | 'phone/settings'
  | 'push-notification/providers/apns' | 'push-notification/providers/fcm' | 'push-notification/providers/fcmv1'
  | 'push-notification/providers/sns' | 'push-notification/selected-provider' | 'duo/settings'

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly errorCode: string,
    message: string,
    // retryAfter is the Retry-After header of a 429, in seconds.
    readonly retryAfter?: number,
  ) {
    super(message)
  }
}

type Query = Record<string, string | number | boolean | undefined>
type RequestOptions = { query?: Query; body?: unknown }

export type BrandingPreview = { html: string; warnings: string[] }
export type BrandingObject = Record<string, unknown>

export class Api {
  private forbiddenListeners = new Set<() => Promise<void>>()

  onForbidden(listener: () => Promise<void>): () => void {
    this.forbiddenListeners.add(listener)
    return () => { this.forbiddenListeners.delete(listener) }
  }

  constructor(
    // systemOrigin is where the system API lives (the console's origin).
    private systemOrigin: string,
    private token: () => Promise<string>,
    private fetchFn: typeof fetch = (...a) => window.fetch(...a),
    private baseDomain = '',
  ) {}

  // body is JSON, or a FormData sent as multipart (its boundary is the browser's).
  private async request<T>(origin: string, method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const url = new URL(path, origin)
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined && v !== '') url.searchParams.set(k, String(v))
    }
    const headers: Record<string, string> = { Authorization: 'Bearer ' + (await this.token()) }
    const form = typeof FormData !== 'undefined' && opts.body instanceof FormData
    if (opts.body !== undefined && !form) headers['Content-Type'] = 'application/json'
    const res = await this.fetchFn(url.toString(), {
      method,
      headers,
      body: opts.body === undefined ? undefined : form ? (opts.body as FormData) : JSON.stringify(opts.body),
    })
    if (res.status === 204) return undefined as T
    const body = (await res.json().catch(() => null)) as unknown
    if (!res.ok) {
      // Discovery failures cannot recursively trigger their own refresh.
      if (res.status === 403 && path !== '/api/console/tenants') {
        await Promise.allSettled([...this.forbiddenListeners].map((listener) => listener()))
      }
      const e = (body ?? {}) as Partial<ManagementError>
      const wait = Number(res.headers.get('Retry-After'))
      throw new ApiError(res.status, e.errorCode ?? '', e.message ?? res.statusText ?? 'Request failed', wait > 0 ? wait : undefined)
    }
    return body as T
  }

  private tenantRequest<T>(t: SystemTenant, method: string, path: string, opts?: RequestOptions): Promise<T> {
    const origin = 'https://' + t.host
    if (origin === this.systemOrigin || (this.baseDomain && t.host === `${t.name}.${this.baseDomain}`)) {
      return this.request(origin, method, path, opts)
    }
    return this.request(this.systemOrigin, method, `/api/console/tenants/${encodeURIComponent(t.name)}${path}`, opts)
  }

  getBrandingResource<T = BrandingObject>(t: SystemTenant, resource: string): Promise<T> {
    return this.tenantRequest(t, 'GET', '/api/v2/' + resource)
  }
  writeBrandingResource<T = BrandingObject>(t: SystemTenant, method: 'PATCH' | 'PUT' | 'POST' | 'DELETE', resource: string, body?: unknown): Promise<T> {
    return this.tenantRequest(t, method, '/api/v2/' + resource, { body })
  }
  previewTenantBranding(t: SystemTenant, body: { screen: string; language: string; overrides?: BrandingObject }): Promise<BrandingPreview> {
    return this.request(this.systemOrigin, 'POST', '/api/system/tenants/' + encodeURIComponent(t.name) + '/branding/preview', { body })
  }

  getGuardianFactors(t: SystemTenant): Promise<GuardianFactors> {
    return this.tenantRequest(t, 'GET', '/api/v2/guardian/factors')
  }
  setGuardianFactor(t: SystemTenant, name: NonNullable<GuardianFactors[number]['name']>, enabled: boolean): Promise<components['schemas']['MFASetGuardianFactorResponse']> {
    return this.tenantRequest(t, 'PUT', '/api/v2/guardian/factors/' + encodeURIComponent(name), { body: { enabled } })
  }
  getGuardianPolicies(t: SystemTenant): Promise<GuardianPolicies> {
    return this.tenantRequest(t, 'GET', '/api/v2/guardian/policies')
  }
  setGuardianPolicies(t: SystemTenant, body: GuardianPolicies): Promise<GuardianPolicies> {
    return this.tenantRequest(t, 'PUT', '/api/v2/guardian/policies', { body })
  }
  getGuardianConfiguration(t: SystemTenant, route: GuardianConfigurationRoute): Promise<GuardianConfiguration> {
    return this.tenantRequest(t, 'GET', '/api/v2/guardian/factors/' + route)
  }
  setGuardianConfiguration(t: SystemTenant, route: GuardianConfigurationRoute, body: GuardianConfiguration): Promise<GuardianConfiguration> {
    return this.tenantRequest(t, 'PUT', '/api/v2/guardian/factors/' + route, { body })
  }
  getAuthenticationMethods(t: SystemTenant, id: string, page: number): Promise<ConsoleAuthenticationMethod[] | { authenticators?: ConsoleAuthenticationMethod[]; total?: number }> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/users/${encodeURIComponent(id)}/authentication-methods`, { query: { page, per_page: 100, include_totals: true } })
  }
  renameAuthenticationMethod(t: SystemTenant, id: string, method: string, name: string): Promise<ConsoleAuthenticationMethod> {
    return this.request(this.systemOrigin, 'PATCH', `/api/system/tenants/${encodeURIComponent(t.name)}/users/${encodeURIComponent(id)}/authentication-methods/${encodeURIComponent(method)}`, { body: { name } })
  }
  getPasskeyPrerequisites(t: SystemTenant, id: string): Promise<{ effective: boolean; unmet: string[] }> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/connections/${encodeURIComponent(id)}/passkey-prerequisites`)
  }
  getRelyingPartyIds(t: SystemTenant): Promise<ConsoleRelyingPartyId[]> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/relying-party-ids`)
  }
  getRoamingUV(t: SystemTenant): Promise<components['schemas']['RoamingUVSettings']> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/guardian/factors/webauthn-roaming/settings`)
  }
  setRoamingUV(t: SystemTenant, user_verification: 'discouraged' | 'preferred' | 'required'): Promise<components['schemas']['RoamingUVSettings']> {
    return this.request(this.systemOrigin, 'PUT', `/api/system/tenants/${encodeURIComponent(t.name)}/guardian/factors/webauthn-roaming/settings`, { body: { user_verification } })
  }
  deleteAuthenticationMethod(t: SystemTenant, id: string, method?: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', userPath(id) + '/authentication-methods' + (method ? '/' + encodeURIComponent(method) : ''))
  }
  regenerateRecoveryCode(t: SystemTenant, id: string): Promise<components['schemas']['MFACreateUserRecoveryCodeResponse']> {
    return this.tenantRequest(t, 'POST', userPath(id) + '/recovery-code-regeneration')
  }
  invalidateRememberBrowser(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'POST', userPath(id) + '/multifactor/actions/invalidate-remember-browser')
  }
  inviteMfa(t: SystemTenant, body: components['schemas']['MFACreateGuardianEnrollmentTicketRequest']): Promise<components['schemas']['MFACreateGuardianEnrollmentTicketResponse']> {
    return this.tenantRequest(t, 'POST', '/api/v2/guardian/enrollments/ticket', { body })
  }

  getTenantSettings(t: SystemTenant): Promise<TenantSettings> {
    return this.tenantRequest(t, 'GET', '/api/v2/tenants/settings')
  }
  updateTenantSettings(t: SystemTenant, body: TenantSettingsPatch): Promise<TenantSettings> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/tenants/settings', { body })
  }
  listCustomDomains(t: SystemTenant): Promise<CustomDomain[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/custom-domains')
  }
  createCustomDomain(t: SystemTenant, body: CustomDomainCreate): Promise<CustomDomain> {
    return this.tenantRequest(t, 'POST', '/api/v2/custom-domains', { body })
  }
  getCustomDomain(t: SystemTenant, id: string): Promise<CustomDomain> {
    return this.tenantRequest(t, 'GET', '/api/v2/custom-domains/' + encodeURIComponent(id))
  }
  updateCustomDomain(t: SystemTenant, id: string, body: CustomDomainUpdate): Promise<CustomDomain> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/custom-domains/' + encodeURIComponent(id), { body })
  }
  deleteCustomDomain(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/custom-domains/' + encodeURIComponent(id))
  }
  // verifyCustomDomain is never retried: only its first successful reply can
  // carry the one-time proxy key.
  verifyCustomDomain(t: SystemTenant, id: string): Promise<CustomDomainVerified> {
    return this.tenantRequest(t, 'POST', '/api/v2/custom-domains/' + encodeURIComponent(id) + '/verify')
  }
  testCustomDomain(t: SystemTenant, id: string): Promise<CustomDomainTest> {
    return this.tenantRequest(t, 'POST', '/api/v2/custom-domains/' + encodeURIComponent(id) + '/test')
  }
  getDefaultCustomDomain(t: SystemTenant): Promise<CustomDomain> {
    return this.tenantRequest(t, 'GET', '/api/v2/custom-domains/default')
  }
  setDefaultCustomDomain(t: SystemTenant, domain: string): Promise<CustomDomain> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/custom-domains/default', { body: { domain } })
  }
  listSigningKeys(t: SystemTenant): Promise<ManagedSigningKey[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/keys/signing')
  }
  getSigningKey(t: SystemTenant, kid: string): Promise<ManagedSigningKey> {
    return this.tenantRequest(t, 'GET', '/api/v2/keys/signing/' + encodeURIComponent(kid))
  }
  rotateSigningKeys(t: SystemTenant): Promise<ManagedSigningKey> {
    return this.tenantRequest(t, 'POST', '/api/v2/keys/signing/rotate')
  }
  revokeSigningKey(t: SystemTenant, kid: string): Promise<ManagedSigningKey> {
    return this.tenantRequest(t, 'PUT', '/api/v2/keys/signing/' + encodeURIComponent(kid) + '/revoke')
  }
  getCustomSigningKeys(t: SystemTenant): Promise<CustomSigningJWKS> {
    return this.tenantRequest(t, 'GET', '/api/v2/keys/custom-signing')
  }
  putCustomSigningKeys(t: SystemTenant, body: CustomSigningJWKS): Promise<CustomSigningJWKS> {
    return this.tenantRequest(t, 'PUT', '/api/v2/keys/custom-signing', { body })
  }
  deleteCustomSigningKeys(t: SystemTenant): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/keys/custom-signing')
  }
  getUserBlocks(t: SystemTenant, id: string): Promise<UserBlocks> {
    return this.tenantRequest(t, 'GET', '/api/v2/user-blocks/' + encodeURIComponent(id))
  }
  deleteUserBlocks(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/user-blocks/' + encodeURIComponent(id))
  }
  getIPBlock(t: SystemTenant, ip: string): Promise<void> {
    return this.tenantRequest(t, 'GET', '/api/v2/anomaly/blocks/ips/' + encodeURIComponent(ip))
  }
  deleteIPBlock(t: SystemTenant, ip: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/anomaly/blocks/ips/' + encodeURIComponent(ip))
  }
  getBruteForceProtection(t: SystemTenant): Promise<BruteForceProtection> {
    return this.tenantRequest(t, 'GET', '/api/v2/attack-protection/brute-force-protection')
  }
  updateBruteForceProtection(t: SystemTenant, body: BruteForceProtectionUpdate): Promise<BruteForceProtection> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/attack-protection/brute-force-protection', { body })
  }
  getSuspiciousIpThrottling(t: SystemTenant): Promise<SuspiciousIpThrottling> {
    return this.tenantRequest(t, 'GET', '/api/v2/attack-protection/suspicious-ip-throttling')
  }
  updateSuspiciousIpThrottling(t: SystemTenant, body: SuspiciousIpThrottlingUpdate): Promise<SuspiciousIpThrottling> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/attack-protection/suspicious-ip-throttling', { body })
  }
  getBreachedPasswordDetection(t: SystemTenant): Promise<BreachedPasswordDetection> {
    return this.tenantRequest(t, 'GET', '/api/v2/attack-protection/breached-password-detection')
  }
  updateBreachedPasswordDetection(t: SystemTenant, body: BreachedPasswordDetectionUpdate): Promise<BreachedPasswordDetection> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/attack-protection/breached-password-detection', { body })
  }
  getBotDetection(t: SystemTenant): Promise<BotDetection> {
    return this.tenantRequest(t, 'GET', '/api/v2/attack-protection/bot-detection')
  }
  updateBotDetection(t: SystemTenant, body: BotDetectionUpdate): Promise<BotDetection> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/attack-protection/bot-detection', { body })
  }
  getCaptcha(t: SystemTenant): Promise<Captcha> {
    return this.tenantRequest(t, 'GET', '/api/v2/attack-protection/captcha')
  }
  updateCaptcha(t: SystemTenant, body: CaptchaUpdate): Promise<Captcha> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/attack-protection/captcha', { body })
  }

  listOrganizations(t: SystemTenant, page: number, userId?: string): Promise<OrganizationsPage> {
    const path = userId === undefined ? '/api/v2/organizations' : userPath(userId) + '/organizations'
    return this.tenantRequest(t, 'GET', path, { query: { page, per_page: 20, include_totals: true } })
  }
  searchOrganizations(t: SystemTenant, q: string, parser: 'lucene' | 'scim', from?: string): Promise<components['schemas']['IISearchOrganizationsPaginatedResponseContent']> {
    return this.tenantRequest(t, 'GET', '/api/v2/organizations/search', { query: { q, parser, from, take: 20 } })
  }
  organizationPath(id: string, resource: string): string { return '/api/v2/organizations/' + encodeURIComponent(id) + '/' + resource }
  listOrganizationInvitations(t: SystemTenant, id: string, page: number): Promise<components['schemas']['IIListOrganizationInvitationsOffsetPaginatedResponseContent']> {
    return this.tenantRequest(t, 'GET', this.organizationPath(id, 'invitations'), { query: { page, per_page: 20, include_totals: true } })
  }
  createOrganizationInvitation(t: SystemTenant, id: string, body: OrganizationInvitationCreate): Promise<OrganizationInvitation> {
    return this.tenantRequest(t, 'POST', this.organizationPath(id, 'invitations'), { body })
  }
  deleteOrganizationInvitation(t: SystemTenant, id: string, invitationId: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', this.organizationPath(id, 'invitations/' + encodeURIComponent(invitationId)))
  }
  listOrganizationClients(t: SystemTenant, id: string, from?: string): Promise<components['schemas']['IIListOrganizationClientsResponseContent']> {
    return this.tenantRequest(t, 'GET', this.organizationPath(id, 'clients'), { query: { take: 20, from } })
  }
  associateOrganizationClient(t: SystemTenant, id: string, clientId: string, memberAccess: boolean): Promise<unknown> {
    return this.tenantRequest(t, 'POST', this.organizationPath(id, 'clients'), { body: { clients: [{ client_id: clientId, use_for_member_access: memberAccess }] } })
  }
  updateOrganizationClient(t: SystemTenant, id: string, clientId: string, memberAccess: boolean): Promise<unknown> {
    return this.tenantRequest(t, 'PATCH', this.organizationPath(id, 'clients/' + encodeURIComponent(clientId)), { body: { use_for_member_access: memberAccess } })
  }
  deleteOrganizationClient(t: SystemTenant, id: string, clientId: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', this.organizationPath(id, 'clients'), { body: { clients: [clientId] } })
  }
  listOrganizationGrants(t: SystemTenant, id: string, page: number): Promise<components['schemas']['OrganizationClientGrantsPage']> {
    return this.tenantRequest(t, 'GET', this.organizationPath(id, 'client-grants'), { query: { page, per_page: 20, include_totals: true } })
  }
  changeOrganizationGrant(t: SystemTenant, id: string, grantId: string, method: 'POST' | 'DELETE'): Promise<unknown> {
    return this.tenantRequest(t, method, this.organizationPath(id, 'client-grants' + (method === 'DELETE' ? '/' + encodeURIComponent(grantId) : '')), { body: method === 'POST' ? { grant_id: grantId } : undefined })
  }
  listOrganizationDomains(t: SystemTenant, id: string, from?: string): Promise<components['schemas']['IIListOrganizationDiscoveryDomainsResponseContent']> {
    return this.tenantRequest(t, 'GET', this.organizationPath(id, 'discovery-domains'), { query: { take: 20, from } })
  }
  createOrganizationDomain(t: SystemTenant, id: string, body: components['schemas']['IICreateOrganizationDiscoveryDomainRequestContent']): Promise<OrganizationDiscoveryDomain> {
    return this.tenantRequest(t, 'POST', this.organizationPath(id, 'discovery-domains'), { body })
  }
  updateOrganizationDomain(t: SystemTenant, id: string, domainId: string, body: components['schemas']['IIUpdateOrganizationDiscoveryDomainRequestContent']): Promise<OrganizationDiscoveryDomain> {
    return this.tenantRequest(t, 'PATCH', this.organizationPath(id, 'discovery-domains/' + encodeURIComponent(domainId)), { body })
  }
  deleteOrganizationDomain(t: SystemTenant, id: string, domainId: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', this.organizationPath(id, 'discovery-domains/' + encodeURIComponent(domainId)))
  }
  listAllOrganizationConnections(t: SystemTenant, id: string): Promise<components['schemas']['OrganizationConnectionsPage']> {
    return this.tenantRequest(t, 'GET', this.organizationPath(id, 'connections'), { query: { page: 0, per_page: 50, include_totals: true } })
  }
  changeAllOrganizationConnection(t: SystemTenant, id: string, connectionId: string, method: 'POST' | 'PATCH' | 'DELETE', body?: OrganizationConnectionUpdate): Promise<unknown> {
    return this.tenantRequest(t, method, this.organizationPath(id, 'connections' + (method === 'POST' ? '' : '/' + encodeURIComponent(connectionId))), { body: method === 'POST' ? { connection_id: connectionId, ...body } : body })
  }
  getOrganization(t: SystemTenant, id: string): Promise<Organization> {
    return this.tenantRequest(t, 'GET', '/api/v2/organizations/' + encodeURIComponent(id))
  }
  createOrganization(t: SystemTenant, body: OrganizationCreate): Promise<Organization> {
    return this.tenantRequest(t, 'POST', '/api/v2/organizations', { body })
  }
  updateOrganization(t: SystemTenant, id: string, body: OrganizationUpdate): Promise<Organization> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/organizations/' + encodeURIComponent(id), { body })
  }
  deleteOrganization(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/organizations/' + encodeURIComponent(id))
  }
  listOrganizationConnections(t: SystemTenant, id: string, page: number, per_page = 20): Promise<OrganizationEnabledConnectionsPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/organizations/' + encodeURIComponent(id) + '/enabled_connections', { query: { page, per_page, include_totals: true } })
  }
  changeOrganizationConnection(t: SystemTenant, id: string, method: 'POST' | 'PATCH' | 'DELETE', connectionId: string, body?: OrganizationEnabledConnectionUpdate): Promise<void> {
    const path = '/api/v2/organizations/' + encodeURIComponent(id) + '/enabled_connections'
    return this.tenantRequest(t, method, path + (method === 'POST' ? '' : '/' + encodeURIComponent(connectionId)), { body: method === 'POST' ? { ...body, connection_id: connectionId } : body })
  }
  listOrganizationMembers(t: SystemTenant, id: string, page: number): Promise<OrganizationMembersPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/organizations/' + encodeURIComponent(id) + '/members', { query: { page, per_page: 20, include_totals: true } })
  }
  changeOrganizationMembers(t: SystemTenant, id: string, method: 'POST' | 'DELETE', members: string[]): Promise<void> {
    return this.tenantRequest(t, method, '/api/v2/organizations/' + encodeURIComponent(id) + '/members', { body: { members } })
  }
  listOrganizationMemberRoles(t: SystemTenant, id: string, userId: string, page: number): Promise<RolePage> {
    return this.tenantRequest(t, 'GET', '/api/v2/organizations/' + encodeURIComponent(id) + '/members/' + encodeURIComponent(userId) + '/roles', { query: { page, per_page: 20, include_totals: true } })
  }
  changeOrganizationMemberRoles(t: SystemTenant, id: string, userId: string, method: 'POST' | 'DELETE', roles: string[]): Promise<void> {
    return this.tenantRequest(t, method, '/api/v2/organizations/' + encodeURIComponent(id) + '/members/' + encodeURIComponent(userId) + '/roles', { body: { roles } })
  }

  listRoles(t: SystemTenant, q: OffsetPage & { name_filter?: string }): Promise<RolePage> {
    return this.tenantRequest(t, 'GET', '/api/v2/roles', { query: { ...q, include_totals: true } })
  }
  getRole(t: SystemTenant, id: string): Promise<Role> {
    return this.tenantRequest(t, 'GET', '/api/v2/roles/' + encodeURIComponent(id))
  }
  createRole(t: SystemTenant, body: { name: string; description: string }): Promise<Role> {
    return this.tenantRequest(t, 'POST', '/api/v2/roles', { body })
  }
  updateRole(t: SystemTenant, id: string, body: { name?: string; description?: string }): Promise<Role> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/roles/' + encodeURIComponent(id), { body })
  }
  deleteRole(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/roles/' + encodeURIComponent(id))
  }
  listRoleUsers(t: SystemTenant, id: string, q: OffsetPage): Promise<RoleUserPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/roles/' + encodeURIComponent(id) + '/users', { query: { ...q, include_totals: true } })
  }
  assignRoleUsers(t: SystemTenant, id: string, users: string[]): Promise<void> {
    return this.tenantRequest(t, 'POST', '/api/v2/roles/' + encodeURIComponent(id) + '/users', { body: { users } })
  }
  listUserRoles(t: SystemTenant, id: string, q: OffsetPage): Promise<RolePage> {
    return this.tenantRequest(t, 'GET', userPath(id) + '/roles', { query: { ...q, include_totals: true } })
  }
  changeUserRoles(t: SystemTenant, id: string, method: 'POST' | 'DELETE', roles: string[]): Promise<void> {
    return this.tenantRequest(t, method, userPath(id) + '/roles', { body: { roles } })
  }
  // Directory groups (Plan 37c).
  listGroups(t: SystemTenant, q: OffsetPage & { search?: string; connection_id?: string }): Promise<GroupPage> {
    const query: Record<string, string | number | boolean> = { page: q.page, per_page: q.per_page, include_totals: true }
    if (q.search) query.search = q.search
    if (q.connection_id) query.connection_id = q.connection_id
    return this.tenantRequest(t, 'GET', '/api/v2/groups', { query })
  }
  getGroup(t: SystemTenant, id: string): Promise<Group> {
    return this.tenantRequest(t, 'GET', '/api/v2/groups/' + encodeURIComponent(id))
  }
  deleteGroup(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/groups/' + encodeURIComponent(id))
  }
  listGroupMembers(t: SystemTenant, id: string, from?: string): Promise<GroupMemberPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/groups/' + encodeURIComponent(id) + '/members', { query: from ? { take: 50, from } : { take: 50 } })
  }
  listGroupRoles(t: SystemTenant, id: string): Promise<GroupRolePage> {
    return this.tenantRequest(t, 'GET', '/api/v2/groups/' + encodeURIComponent(id) + '/roles', { query: { take: 100 } })
  }
  changeGroupRoles(t: SystemTenant, id: string, method: 'POST' | 'DELETE', roles: string[]): Promise<void> {
    return this.tenantRequest(t, method, '/api/v2/groups/' + encodeURIComponent(id) + '/roles', { body: { roles } })
  }
  listRoleGroups(t: SystemTenant, id: string): Promise<GroupCheckpoint> {
    return this.tenantRequest(t, 'GET', '/api/v2/roles/' + encodeURIComponent(id) + '/groups', { query: { take: 100 } })
  }
  listUserGroups(t: SystemTenant, id: string): Promise<UserGroupPage> {
    return this.tenantRequest(t, 'GET', userPath(id) + '/groups', { query: { take: 100 } })
  }
  // Self-service SSO (Plan 37c Phase B).
  listSelfServiceProfiles(t: SystemTenant): Promise<SelfServiceProfile[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/self-service-profiles', { query: { per_page: 100 } })
  }
  getSelfServiceProfile(t: SystemTenant, id: string): Promise<SelfServiceProfile> {
    return this.tenantRequest(t, 'GET', '/api/v2/self-service-profiles/' + encodeURIComponent(id))
  }
  createSelfServiceProfile(t: SystemTenant, body: SelfServiceProfileCreate): Promise<SelfServiceProfile> {
    return this.tenantRequest(t, 'POST', '/api/v2/self-service-profiles', { body })
  }
  updateSelfServiceProfile(t: SystemTenant, id: string, body: SelfServiceProfileUpdate): Promise<SelfServiceProfile> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/self-service-profiles/' + encodeURIComponent(id), { body })
  }
  deleteSelfServiceProfile(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/self-service-profiles/' + encodeURIComponent(id))
  }
  getSelfServiceCustomText(t: SystemTenant, id: string): Promise<Record<string, string>> {
    return this.tenantRequest(t, 'GET', '/api/v2/self-service-profiles/' + encodeURIComponent(id) + '/custom-text/en/get-started')
  }
  setSelfServiceCustomText(t: SystemTenant, id: string, body: Record<string, string>): Promise<Record<string, string>> {
    return this.tenantRequest(t, 'PUT', '/api/v2/self-service-profiles/' + encodeURIComponent(id) + '/custom-text/en/get-started', { body })
  }
  createSsoTicket(t: SystemTenant, id: string, body: SsoTicketRequest): Promise<{ ticket?: string }> {
    return this.tenantRequest(t, 'POST', '/api/v2/self-service-profiles/' + encodeURIComponent(id) + '/sso-ticket', { body })
  }
  revokeSsoTicket(t: SystemTenant, id: string, ticket: string): Promise<void> {
    return this.tenantRequest(t, 'POST', '/api/v2/self-service-profiles/' + encodeURIComponent(id) + '/sso-ticket/' + encodeURIComponent(ticket) + '/revoke')
  }
  listConnectionProfiles(t: SystemTenant): Promise<{ connection_profiles?: ConnectionProfile[]; next?: string }> {
    return this.tenantRequest(t, 'GET', '/api/v2/connection-profiles', { query: { take: 100 } })
  }
  createConnectionProfile(t: SystemTenant, body: ConnectionProfileCreate): Promise<ConnectionProfile> {
    return this.tenantRequest(t, 'POST', '/api/v2/connection-profiles', { body })
  }
  deleteConnectionProfile(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/connection-profiles/' + encodeURIComponent(id))
  }
  // SCIM provisioning of an enterprise connection (Plan 37c).
  getScimConfiguration(t: SystemTenant, connection: string): Promise<ScimConfiguration> {
    return this.tenantRequest(t, 'GET', scimPath(connection))
  }
  createScimConfiguration(t: SystemTenant, connection: string): Promise<ScimConfiguration> {
    return this.tenantRequest(t, 'POST', scimPath(connection), { body: {} })
  }
  updateScimConfiguration(t: SystemTenant, connection: string, body: { user_id_attribute: string; mapping: ScimMappingItem[] }): Promise<ScimConfiguration> {
    return this.tenantRequest(t, 'PATCH', scimPath(connection), { body })
  }
  getScimDefaultMapping(t: SystemTenant, connection: string): Promise<{ mapping?: ScimMappingItem[] }> {
    return this.tenantRequest(t, 'GET', scimPath(connection) + '/default-mapping')
  }
  deleteScimConfiguration(t: SystemTenant, connection: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', scimPath(connection))
  }
  listScimTokens(t: SystemTenant, connection: string): Promise<ScimToken[]> {
    return this.tenantRequest(t, 'GET', scimPath(connection) + '/tokens')
  }
  createScimToken(t: SystemTenant, connection: string, body: ScimTokenCreate): Promise<ScimTokenCreated> {
    return this.tenantRequest(t, 'POST', scimPath(connection) + '/tokens', { body })
  }
  deleteScimToken(t: SystemTenant, connection: string, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', scimPath(connection) + '/tokens/' + encodeURIComponent(id))
  }
  // Google Workspace directory provisioning (Plan 37c Phase C).
  getDirectoryProvisioning(t: SystemTenant, connection: string): Promise<DirectoryProvisioning> {
    return this.tenantRequest(t, 'GET', dirPath(connection))
  }
  createDirectoryProvisioning(t: SystemTenant, connection: string, body: DirectoryProvisioningUpdate = {}): Promise<DirectoryProvisioning> {
    return this.tenantRequest(t, 'POST', dirPath(connection), { body })
  }
  updateDirectoryProvisioning(t: SystemTenant, connection: string, body: DirectoryProvisioningUpdate): Promise<DirectoryProvisioning> {
    return this.tenantRequest(t, 'PATCH', dirPath(connection), { body })
  }
  deleteDirectoryProvisioning(t: SystemTenant, connection: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', dirPath(connection))
  }
  getDirectoryDefaultMapping(t: SystemTenant, connection: string): Promise<{ mapping?: DirectoryMappingItem[] }> {
    return this.tenantRequest(t, 'GET', dirPath(connection) + '/default-mapping')
  }
  synchronizeDirectory(t: SystemTenant, connection: string): Promise<{ connection_id: string; synchronization_id: string; status: string }> {
    return this.tenantRequest(t, 'POST', dirPath(connection) + '/synchronizations', { body: {} })
  }
  listSynchronizedGroups(t: SystemTenant, connection: string): Promise<{ groups: SynchronizedGroup[]; next?: string }> {
    return this.tenantRequest(t, 'GET', dirPath(connection) + '/synchronized-groups?take=100')
  }
  replaceSynchronizedGroups(t: SystemTenant, connection: string, groups: SynchronizedGroup[]): Promise<void> {
    return this.tenantRequest(t, 'PUT', dirPath(connection) + '/synchronized-groups', { body: { groups } })
  }
  // directoryConsentLink is a system API extension: a 15-minute link a
  // Google Workspace administrator opens to grant directory access.
  directoryConsentLink(t: Pick<SystemTenant, 'name'>, connection: string): Promise<{ url: string; redirect_uri: string; expires_at: string }> {
    const path = `/api/system/tenants/${encodeURIComponent(t.name)}/connections/${encodeURIComponent(connection)}/directory-provisioning/consent`
    return this.request(this.systemOrigin, 'POST', path, {})
  }
  listPermissions(t: SystemTenant, kind: 'roles' | 'users', id: string, q: OffsetPage): Promise<PermissionPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/' + kind + '/' + encodeURIComponent(id) + '/permissions', { query: { ...q, include_totals: true } })
  }
  changePermissions(t: SystemTenant, kind: 'roles' | 'users', id: string, method: 'POST' | 'DELETE', permissions: PermissionKey[]): Promise<void> {
    return this.tenantRequest(t, method, '/api/v2/' + kind + '/' + encodeURIComponent(id) + '/permissions', { body: { permissions } })
  }

  listClients(t: SystemTenant, q: { page: number; per_page: number; app_type?: string }): Promise<ClientPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/clients', { query: { ...q, include_totals: true, fields: 'client_secret', include_fields: false } })
  }

  getClient(t: SystemTenant, id: string): Promise<Client> {
    return this.tenantRequest(t, 'GET', '/api/v2/clients/' + encodeURIComponent(id))
  }

  createClient(t: SystemTenant, body: ClientCreate): Promise<Client> {
    return this.tenantRequest(t, 'POST', '/api/v2/clients', { body })
  }

  updateClient(t: SystemTenant, id: string, body: ClientUpdate): Promise<Client> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/clients/' + encodeURIComponent(id), { body })
  }

  listClientCredentials(t: SystemTenant, id: string): Promise<ClientCredential[]> {
    return this.tenantRequest(t, 'GET', credentialsPath(id))
  }

  createClientCredential(t: SystemTenant, id: string, body: ClientCredentialCreate): Promise<ClientCredential> {
    return this.tenantRequest(t, 'POST', credentialsPath(id), { body })
  }

  updateClientCredential(t: SystemTenant, id: string, credentialId: string, body: ClientCredentialUpdate): Promise<ClientCredential> {
    return this.tenantRequest(t, 'PATCH', credentialsPath(id) + '/' + encodeURIComponent(credentialId), { body })
  }

  deleteClientCredential(t: SystemTenant, id: string, credentialId: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', credentialsPath(id) + '/' + encodeURIComponent(credentialId))
  }

  listTokenExchangeProfiles(t: SystemTenant, q: { from?: string; take: number }): Promise<TokenExchangeProfilePage> {
    return this.tenantRequest(t, 'GET', '/api/v2/token-exchange-profiles', { query: q })
  }

  createTokenExchangeProfile(t: SystemTenant, body: TokenExchangeProfileCreate): Promise<TokenExchangeProfile> {
    return this.tenantRequest(t, 'POST', '/api/v2/token-exchange-profiles', { body })
  }

  updateTokenExchangeProfile(t: SystemTenant, id: string, body: TokenExchangeProfileUpdate): Promise<TokenExchangeProfile> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/token-exchange-profiles/' + encodeURIComponent(id), { body })
  }

  deleteTokenExchangeProfile(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/token-exchange-profiles/' + encodeURIComponent(id))
  }

  async allTokenExchangeProfiles(t: SystemTenant): Promise<TokenExchangeProfile[]> {
    const out: TokenExchangeProfile[] = []
    let from: string | undefined
    do {
      const r = await this.listTokenExchangeProfiles(t, { from, take: 100 })
      out.push(...r.token_exchange_profiles)
      from = r.next
    } while (from)
    return out
  }

  deleteClient(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/clients/' + encodeURIComponent(id))
  }

  rotateSecret(t: SystemTenant, id: string): Promise<Client> {
    return this.tenantRequest(t, 'POST', '/api/v2/clients/' + encodeURIComponent(id) + '/rotate-secret')
  }

  listResourceServers(t: SystemTenant, q: { page: number; per_page: number }): Promise<ResourceServerPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/resource-servers', { query: { ...q, include_totals: true } })
  }

  getResourceServer(t: SystemTenant, id: string): Promise<ResourceServer> {
    return this.tenantRequest(t, 'GET', '/api/v2/resource-servers/' + encodeURIComponent(id))
  }

  createResourceServer(t: SystemTenant, body: ResourceServerCreate): Promise<ResourceServer> {
    return this.tenantRequest(t, 'POST', '/api/v2/resource-servers', { body })
  }

  updateResourceServer(t: SystemTenant, id: string, body: ResourceServerUpdate): Promise<ResourceServer> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/resource-servers/' + encodeURIComponent(id), { body })
  }

  deleteResourceServer(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/resource-servers/' + encodeURIComponent(id))
  }

  listClientGrants(t: SystemTenant, q: { page: number; per_page: number; client_id?: string; audience?: string }): Promise<ClientGrantPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/client-grants', { query: { ...q, include_totals: true } })
  }

  createClientGrant(t: SystemTenant, body: ClientGrantCreate): Promise<ClientGrant> {
    return this.tenantRequest(t, 'POST', '/api/v2/client-grants', { body })
  }

  updateClientGrant(t: SystemTenant, id: string, body: ClientGrantUpdate): Promise<ClientGrant> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/client-grants/' + encodeURIComponent(id), { body })
  }

  deleteClientGrant(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/client-grants/' + encodeURIComponent(id))
  }

  listConnections(t: SystemTenant, q: { page: number; per_page: number; strategy?: string; fields?: string }): Promise<ConnectionPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/connections', { query: { fields: 'id,name,strategy,is_domain_connection', ...q, include_fields: true, include_totals: true } })
  }

  // The console's connection filter is separate from the user's v3 query text.
  listUsers(t: SystemTenant, params: { q?: string; page: number; per_page: number; sort?: string; connection?: string }): Promise<UserPage> {
    const { connection, ...query } = params
    return this.tenantRequest(t, 'GET', '/api/v2/users', { query: { ...query, console_connection: connection, search_engine: 'v3', include_totals: true } })
  }

  createUser(t: SystemTenant, body: UserCreate): Promise<User> {
    return this.tenantRequest(t, 'POST', '/api/v2/users', { body })
  }

  getUser(t: SystemTenant, id: string): Promise<User> {
    return this.tenantRequest(t, 'GET', userPath(id))
  }

  // updateUser sends only what changes. Metadata merges at the top level:
  // a key set to null is removed.
  updateUser(t: SystemTenant, id: string, body: UserUpdate): Promise<User> {
    return this.tenantRequest(t, 'PATCH', userPath(id), { body })
  }

  deleteUser(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', userPath(id))
  }

  // linkUser merges another database user into this one; userId is the
  // secondary's ID without its auth0| prefix.
  linkUser(t: SystemTenant, id: string, userId: string): Promise<UserIdentity[]> {
    return this.tenantRequest(t, 'POST', userPath(id) + '/identities', { body: { provider: 'auth0', user_id: userId } })
  }

  unlinkUser(t: SystemTenant, id: string, provider: string, userId: string): Promise<UserIdentity[]> {
    return this.tenantRequest(t, 'DELETE', userPath(id) + '/identities/' + encodeURIComponent(provider) + '/' + encodeURIComponent(userId))
  }

  listUserSessions(t: SystemTenant, id: string, q: { take: number; from?: string }): Promise<UserSessionPage> {
    return this.tenantRequest(t, 'GET', userPath(id) + '/sessions', { query: q })
  }

  deleteUserSessions(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', userPath(id) + '/sessions')
  }

  deleteSession(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/sessions/' + encodeURIComponent(id))
  }

  revokeSession(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'POST', '/api/v2/sessions/' + encodeURIComponent(id) + '/revoke')
  }

  updateSessionMetadata(t: SystemTenant, id: string, metadata: Record<string, string> | null): Promise<UserSession> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/sessions/' + encodeURIComponent(id), { body: { session_metadata: metadata } })
  }

  updateRefreshTokenMetadata(t: SystemTenant, id: string, metadata: Record<string, string> | null): Promise<UserRefreshToken> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/refresh-tokens/' + encodeURIComponent(id), { body: { refresh_token_metadata: metadata } })
  }

  listUserRefreshTokens(t: SystemTenant, id: string, q: { take: number; from?: string }): Promise<UserRefreshTokenPage> {
    return this.tenantRequest(t, 'GET', userPath(id) + '/refresh-tokens', { query: q })
  }

  deleteUserRefreshTokens(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', userPath(id) + '/refresh-tokens')
  }

  deleteRefreshToken(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/refresh-tokens/' + encodeURIComponent(id))
  }

  listUserGrants(t: SystemTenant, userId: string): Promise<UserGrant[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/grants', { query: { user_id: userId } })
  }

  deleteGrant(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/grants/' + encodeURIComponent(id))
  }

  // The ticket functions return a single-use URL. Callers show it once and
  // must not keep it anywhere but the component that shows it.
  createPasswordChangeTicket(t: SystemTenant, userId: string): Promise<{ ticket: string }> {
    return this.tenantRequest(t, 'POST', '/api/v2/tickets/password-change', { body: { user_id: userId } })
  }

  createVerificationTicket(t: SystemTenant, userId: string): Promise<{ ticket: string }> {
    return this.tenantRequest(t, 'POST', '/api/v2/tickets/email-verification', { body: { user_id: userId } })
  }

  // The jobs. The list is the system API's (Auth0 has none); the rest are
  // the tenant's /api/v2/jobs.
  listJobs(t: Pick<SystemTenant, 'name'>, q: { page: number; per_page: number }): Promise<JobPage> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/jobs`, { query: { ...q, include_totals: true } })
  }

  createImportJob(t: SystemTenant, form: FormData): Promise<Job> {
    return this.tenantRequest(t, 'POST', '/api/v2/jobs/users-imports', { body: form })
  }

  createExportJob(t: SystemTenant, body: UsersExportJobCreate): Promise<Job> {
    return this.tenantRequest(t, 'POST', '/api/v2/jobs/users-exports', { body })
  }

  // getJob reads the job; a completed export carries a new 60-second
  // location on every read, so callers read again for each download.
  getJob(t: SystemTenant, id: string): Promise<Job> {
    return this.tenantRequest(t, 'GET', '/api/v2/jobs/' + encodeURIComponent(id))
  }

  // getJobErrors: the import's failed records (secrets masked by the
  // server), undefined for an export (204), or the job itself when it failed.
  getJobErrors(t: SystemTenant, id: string): Promise<JobError[] | Job | undefined> {
    return this.tenantRequest(t, 'GET', '/api/v2/jobs/' + encodeURIComponent(id) + '/errors')
  }

  createVerificationEmailJob(t: SystemTenant, userId: string): Promise<Job> {
    return this.tenantRequest(t, 'POST', '/api/v2/jobs/verification-email', { body: { user_id: userId } })
  }

  getEmailProvider(t: SystemTenant): Promise<EmailProvider> {
    return this.tenantRequest(t, 'GET', '/api/v2/emails/provider')
  }

  createEmailProvider(t: SystemTenant, body: EmailProviderWrite): Promise<EmailProvider> {
    return this.tenantRequest(t, 'POST', '/api/v2/emails/provider', { body })
  }

  updateEmailProvider(t: SystemTenant, body: EmailProviderWrite): Promise<EmailProvider> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/emails/provider', { body })
  }

  deleteEmailProvider(t: SystemTenant): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/emails/provider')
  }

  getEmailTemplate(t: SystemTenant, name: EmailTemplateName): Promise<EmailTemplate> {
    return this.tenantRequest(t, 'GET', '/api/v2/email-templates/' + encodeURIComponent(name))
  }

  createEmailTemplate(t: SystemTenant, body: EmailTemplate): Promise<EmailTemplate> {
    return this.tenantRequest(t, 'POST', '/api/v2/email-templates', { body })
  }

  putEmailTemplate(t: SystemTenant, name: EmailTemplateName, body: EmailTemplate): Promise<EmailTemplate> {
    return this.tenantRequest(t, 'PUT', '/api/v2/email-templates/' + encodeURIComponent(name), { body })
  }

  previewTenantEmail(t: Pick<SystemTenant, 'name'>, body: { template: EmailTemplateName; overrides?: Record<string, unknown> }): Promise<EmailPreview> {
    return this.request(this.systemOrigin, 'POST', `/api/system/tenants/${encodeURIComponent(t.name)}/emails/preview`, { body })
  }

  testTenantEmail(t: Pick<SystemTenant, 'name'>, body: { template: EmailTemplateName }): Promise<void | { status: string; reason?: string; execution_id?: string }> {
    return this.request(this.systemOrigin, 'POST', `/api/system/tenants/${encodeURIComponent(t.name)}/emails/test`, { body })
  }

  getConnection(t: SystemTenant, id: string): Promise<Connection> {
    return this.tenantRequest(t, 'GET', '/api/v2/connections/' + encodeURIComponent(id))
  }

  getConnectionKeys(t: SystemTenant, id: string): Promise<ConnectionKey[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/connections/' + encodeURIComponent(id) + '/keys')
  }
  createConnectionKeys(t: SystemTenant, id: string, body: Record<string, unknown>): Promise<ConnectionKey[]> {
    return this.tenantRequest(t, 'POST', '/api/v2/connections/' + encodeURIComponent(id) + '/keys', { body })
  }
  rotateConnectionKeys(t: SystemTenant, id: string, body: Record<string, unknown>): Promise<ConnectionKey> {
    return this.tenantRequest(t, 'POST', '/api/v2/connections/' + encodeURIComponent(id) + '/keys/rotate', { body })
  }

  createConnection(t: SystemTenant, body: ConnectionCreate): Promise<Connection> {
    return this.tenantRequest(t, 'POST', '/api/v2/connections', { body })
  }

  updateConnection(t: SystemTenant, id: string, body: ConnectionUpdate): Promise<Connection> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/connections/' + encodeURIComponent(id), { body })
  }

  deleteConnection(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/connections/' + encodeURIComponent(id))
  }

  // Enabled applications are read and changed only through the clients
  // endpoint, never through enabled_clients on PATCH.
  getConnectionClients(t: SystemTenant, id: string, q: { take: number; from?: string }): Promise<{ clients: { client_id: string }[]; next?: string }> {
    return this.tenantRequest(t, 'GET', '/api/v2/connections/' + encodeURIComponent(id) + '/clients', { query: q })
  }

  updateConnectionClients(t: SystemTenant, id: string, body: ConnectionClientStatus[]): Promise<void> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/connections/' + encodeURIComponent(id) + '/clients', { body })
  }

  // tryScript runs one custom database script with test arguments (system
  // API). The answer is for the page only; callers must not keep it.
  tryScript(t: Pick<SystemTenant, 'name'>, id: string, script: string, args: unknown[]): Promise<ScriptTryResult> {
    const path = `/api/system/tenants/${encodeURIComponent(t.name)}/connections/${encodeURIComponent(id)}/scripts/${encodeURIComponent(script)}/try`
    return this.request(this.systemOrigin, 'POST', path, { body: { args } })
  }

  tryConnectionPasswordless(t: Pick<SystemTenant, 'name'>, id: string, body: components['schemas']['PasswordlessTryRequest']): Promise<void> {
    const path = `/api/system/tenants/${encodeURIComponent(t.name)}/connections/${encodeURIComponent(id)}/passwordless/try`
    return this.request(this.systemOrigin, 'POST', path, { body })
  }

  // The *All methods read every page (100 at a time) of a listing that the
  // screens need whole: the APIs and machine-to-machine applications to
  // pick from, and the grants for one API or application.
  async allResourceServers(t: SystemTenant): Promise<ResourceServer[]> {
    return collect((page) => this.listResourceServers(t, { page, per_page: ALL_PER_PAGE }).then((r) => ({ items: r.resource_servers, total: r.total })))
  }

  async allMachineClients(t: SystemTenant): Promise<Client[]> {
    return collect((page) => this.listClients(t, { page, per_page: ALL_PER_PAGE, app_type: 'non_interactive' }).then((r) => ({ items: r.clients, total: r.total })))
  }

  async allClientGrants(t: SystemTenant, filter: { client_id?: string; audience?: string }): Promise<ClientGrant[]> {
    return collect((page) => this.listClientGrants(t, { page, per_page: ALL_PER_PAGE, ...filter }).then((r) => ({ items: r.client_grants, total: r.total })))
  }

  async allConnections(t: SystemTenant): Promise<Connection[]> {
    return collect((page) => this.listConnections(t, { page, per_page: ALL_PER_PAGE }).then((r) => ({ items: r.connections, total: r.total })))
  }

  async allDatabaseConnections(t: SystemTenant): Promise<Connection[]> {
    return collect((page) => this.listConnections(t, { page, per_page: ALL_PER_PAGE, strategy: 'auth0' }).then((r) => ({ items: r.connections, total: r.total })))
  }

  // allConnectionClients follows the checkpoint cursor to the end.
  async allConnectionClients(t: SystemTenant, id: string): Promise<string[]> {
    const out: string[] = []
    let from: string | undefined
    do {
      const r = await this.getConnectionClients(t, id, { take: ALL_PER_PAGE, from })
      out.push(...r.clients.map((c) => c.client_id))
      from = r.next
    } while (from)
    return out
  }

  listActionModules(t: SystemTenant, q: { page: number; per_page: number }): Promise<ActionModulesPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/modules', { query: q })
  }

  createActionModule(t: SystemTenant, body: ActionModuleCreate): Promise<ActionModule> {
    return this.tenantRequest(t, 'POST', '/api/v2/actions/modules', { body })
  }

  getActionModule(t: SystemTenant, id: string): Promise<ActionModule> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id))
  }

  updateActionModule(t: SystemTenant, id: string, body: ActionModuleUpdate): Promise<ActionModule> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/actions/modules/' + encodeURIComponent(id), { body })
  }

  deleteActionModule(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/actions/modules/' + encodeURIComponent(id))
  }

  listActionModuleVersions(t: SystemTenant, id: string, q: { page: number; per_page: number }): Promise<ActionModuleVersionsPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/versions', { query: q })
  }

  getActionModuleVersion(t: SystemTenant, id: string, versionId: string): Promise<ActionModuleVersion> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/versions/' + encodeURIComponent(versionId))
  }

  publishActionModule(t: SystemTenant, id: string): Promise<ActionModuleVersion> {
    return this.tenantRequest(t, 'POST', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/versions')
  }

  rollbackActionModule(t: SystemTenant, id: string, body: { module_version_id: string }): Promise<ActionModule> {
    return this.tenantRequest(t, 'POST', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/rollback', { body })
  }

  listActionModuleActions(t: SystemTenant, id: string, q: { page: number; per_page: number }): Promise<ActionModuleActionsPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/actions', { query: q })
  }

  listActions(t: SystemTenant, q: { page: number; per_page: number; triggerId?: string; actionName?: string; deployed?: boolean }): Promise<ActionsPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/actions', { query: q })
  }

  createAction(t: SystemTenant, body: ActionCreate): Promise<Action> {
    return this.tenantRequest(t, 'POST', '/api/v2/actions/actions', { body })
  }

  getAction(t: SystemTenant, id: string): Promise<Action> {
    return this.tenantRequest(t, 'GET', actionPath(id))
  }

  updateAction(t: SystemTenant, id: string, body: ActionUpdate): Promise<Action> {
    return this.tenantRequest(t, 'PATCH', actionPath(id), { body })
  }

  deleteAction(t: SystemTenant, id: string, force = false): Promise<void> {
    return this.tenantRequest(t, 'DELETE', actionPath(id), { query: { force } })
  }

  deployAction(t: SystemTenant, id: string): Promise<ActionVersion> {
    return this.tenantRequest(t, 'POST', actionPath(id) + '/deploy')
  }

  listActionVersions(t: SystemTenant, id: string, q: { page: number; per_page: number }): Promise<ActionVersionsPage> {
    return this.tenantRequest(t, 'GET', actionPath(id) + '/versions', { query: q })
  }

  getActionVersion(t: SystemTenant, id: string, versionId: string): Promise<ActionVersion> {
    return this.tenantRequest(t, 'GET', actionPath(id) + '/versions/' + encodeURIComponent(versionId))
  }

  deployActionVersion(t: SystemTenant, id: string, versionId: string): Promise<ActionVersion> {
    return this.tenantRequest(t, 'POST', actionPath(id) + '/versions/' + encodeURIComponent(versionId) + '/deploy', { body: { update_draft: false } })
  }

  testAction(t: SystemTenant, id: string, body: ActionTestRequest): Promise<ActionTestResponse> {
    return this.tenantRequest(t, 'POST', actionPath(id) + '/test', { body })
  }

  listActionTriggers(t: SystemTenant): Promise<ActionTriggers> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/triggers')
  }

  listActionBindings(t: SystemTenant, trigger: string, q: { page: number; per_page: number }): Promise<ActionBindingsPage> {
    return this.tenantRequest(t, 'GET', triggerPath(trigger), { query: q })
  }

  updateActionBindings(t: SystemTenant, trigger: string, bindings: ActionBindingInput[]): Promise<ActionBindings> {
    return this.tenantRequest(t, 'PATCH', triggerPath(trigger), { body: { bindings } })
  }

  getActionExecutionAttempt(t: SystemTenant, id: string): Promise<void | { job_id: string; attempt: number }> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/actions/executions/${encodeURIComponent(id)}/attempt`)
  }

  getActionExecution(t: SystemTenant, id: string): Promise<ActionExecution> {
    return this.tenantRequest(t, 'GET', '/api/v2/actions/executions/' + encodeURIComponent(id))
  }

  async allActions(t: SystemTenant, triggerId?: string): Promise<Action[]> {
    return collect(page => this.listActions(t, { page, per_page: ALL_PER_PAGE, triggerId }).then(r => ({ items: r.actions, total: r.total })))
  }

  async allActionBindings(t: SystemTenant, trigger: string): Promise<ActionBinding[]> {
    return collect(page => this.listActionBindings(t, trigger, { page, per_page: ALL_PER_PAGE }).then(r => ({ items: r.bindings, total: r.total })))
  }

  listEventStreams(t: SystemTenant, q: { from?: string; take: number }): Promise<components['schemas']['EventsListEventStreamsResponseContent']> {
    return this.tenantRequest(t, 'GET', '/api/v2/event-streams', { query: q })
  }
  getEventStream(t: SystemTenant, id: string): Promise<EventStream> {
    return this.tenantRequest(t, 'GET', eventStreamPath(id))
  }
  createEventStream(t: SystemTenant, body: EventStreamCreate): Promise<EventStream> {
    return this.tenantRequest(t, 'POST', '/api/v2/event-streams', { body })
  }
  updateEventStream(t: SystemTenant, id: string, body: EventStreamPatch): Promise<EventStream> {
    return this.tenantRequest(t, 'PATCH', eventStreamPath(id), { body })
  }
  deleteEventStream(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', eventStreamPath(id))
  }
  testEventStream(t: SystemTenant, id: string, body: EventTestRequest): Promise<EventTestResult> {
    return this.tenantRequest(t, 'POST', eventStreamPath(id) + '/test', { body })
  }
  listEventDeliveries(t: SystemTenant, id: string, q: EventDeliveryQuery): Promise<components['schemas']['EventsListEventStreamDeliveriesResponseContent']> {
    return this.tenantRequest(t, 'GET', eventStreamPath(id) + '/deliveries', { query: q })
  }
  getEventDelivery(t: SystemTenant, id: string, event: string): Promise<EventDelivery> {
    return this.tenantRequest(t, 'GET', eventStreamPath(id) + '/deliveries/' + encodeURIComponent(event))
  }
  redeliverEvent(t: SystemTenant, id: string, event: string): Promise<void> {
    return this.tenantRequest(t, 'POST', eventStreamPath(id) + '/redeliver/' + encodeURIComponent(event))
  }
  redeliverEvents(t: SystemTenant, id: string, body: EventRedelivery): Promise<EventRedelivery> {
    return this.tenantRequest(t, 'POST', eventStreamPath(id) + '/redeliver', { body })
  }

  listLogs(t: SystemTenant, q: { page: number; per_page: number; q?: string }): Promise<LogPage> {
    return this.tenantRequest(t, 'GET', '/api/v2/logs', { query: { ...q, include_totals: true, sort: 'date:-1' } })
  }

  tailLogs(t: SystemTenant, from?: string): Promise<LogItem[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/logs', { query: { from, take: 100 } })
  }

  getLog(t: SystemTenant, id: string): Promise<LogEvent> {
    return this.tenantRequest(t, 'GET', '/api/v2/logs/' + encodeURIComponent(id))
  }

  logStreamStatus(t: SystemTenant): Promise<StreamStatus[]> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/log-streams/status`)
  }

  listLogStreams(t: SystemTenant): Promise<LogStream[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/log-streams')
  }

  getLogStream(t: SystemTenant, id: string): Promise<LogStream> {
    return this.tenantRequest(t, 'GET', '/api/v2/log-streams/' + encodeURIComponent(id))
  }

  createLogStream(t: SystemTenant, body: LogStreamCreate): Promise<LogStream> {
    return this.tenantRequest(t, 'POST', '/api/v2/log-streams', { body })
  }

  updateLogStream(t: SystemTenant, id: string, body: LogStreamPatch): Promise<LogStream> {
    return this.tenantRequest(t, 'PATCH', '/api/v2/log-streams/' + encodeURIComponent(id), { body })
  }

  deleteLogStream(t: SystemTenant, id: string): Promise<void> {
    return this.tenantRequest(t, 'DELETE', '/api/v2/log-streams/' + encodeURIComponent(id))
  }

  listExecutions(t: SystemTenant, q: { trigger?: string; action?: string; after?: string; take: number }): Promise<SystemExecution[]> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/actions/executions`, { query: q })
  }

  getExecution(t: SystemTenant, id: string): Promise<SystemExecution> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/actions/executions/${encodeURIComponent(id)}`)
  }

  dailyStats(t: SystemTenant, q: { from: string; to: string }): Promise<LogStat[]> {
    return this.tenantRequest(t, 'GET', '/api/v2/stats/daily', { query: q })
  }

  activeUsers(t: SystemTenant): Promise<number> {
    return this.tenantRequest(t, 'GET', '/api/v2/stats/active-users')
  }

  listTenants(): Promise<SystemTenant[]> {
    return this.request(this.systemOrigin, 'GET', '/api/console/tenants')
  }

  listOperators(): Promise<Operator[]> {
    return this.request(this.systemOrigin, 'GET', '/api/system/operators')
  }

  inviteOperator(email: string): Promise<OperatorInvite> {
    return this.request(this.systemOrigin, 'POST', '/api/system/operators', { body: { email } })
  }

  deleteOperator(id: string): Promise<void> {
    return this.request(this.systemOrigin, 'DELETE', '/api/system/operators/' + encodeURIComponent(id))
  }

  createTenant(body: TenantCreate): Promise<SystemTenant> {
    return this.request(this.systemOrigin, 'POST', '/api/system/tenants', { body })
  }
}

const ALL_PER_PAGE = 100

function dirPath(connection: string): string {
  return '/api/v2/connections/' + encodeURIComponent(connection) + '/directory-provisioning'
}

function scimPath(connection: string): string {
  return '/api/v2/connections/' + encodeURIComponent(connection) + '/scim-configuration'
}
function userPath(id: string): string {
  return '/api/v2/users/' + encodeURIComponent(id)
}

async function collect<T>(fetchPage: (page: number) => Promise<{ items: T[]; total: number }>): Promise<T[]> {
  const out: T[] = []
  for (let page = 0; ; page++) {
    const r = await fetchPage(page)
    out.push(...r.items)
    if (r.items.length === 0 || out.length >= r.total) return out
  }
}

function credentialsPath(id: string): string { return '/api/v2/clients/' + encodeURIComponent(id) + '/credentials' }
function actionPath(id: string): string { return '/api/v2/actions/actions/' + encodeURIComponent(id) }
function triggerPath(id: string): string { return '/api/v2/actions/triggers/' + encodeURIComponent(id) + '/bindings' }

function eventStreamPath(id: string): string { return '/api/v2/event-streams/' + encodeURIComponent(id) }
