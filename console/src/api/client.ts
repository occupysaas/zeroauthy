import type { components } from './schema'
import type { Role, RolePage, PermissionKey, PermissionPage, RoleUserPage, OffsetPage } from './rbac'
export type { Role, RolePage, PermissionKey, Permission, PermissionSource, PermissionPage, RoleUser, RoleUserPage } from './rbac'

// A thin, typed wrapper over fetch for the Management API (on each
// tenant's own host) and the system API (on the system host).

export type Client = components['schemas']['Client']
export type ClientCreate = components['schemas']['ClientCreate']
export type ClientUpdate = components['schemas']['ClientUpdate']
export type ClientPage = components['schemas']['ClientPage']
export type AppType = components['schemas']['AppType']
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
export type UserRefreshToken = components['schemas']['UserRefreshToken']
export type UserRefreshTokenPage = components['schemas']['UserRefreshTokenPage']
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

export type BrandingPreview = { html: string; warnings: string[] }
export type BrandingObject = Record<string, unknown>

export class Api {
  constructor(
    // systemOrigin is where the system API lives (the console's origin).
    private systemOrigin: string,
    private token: () => Promise<string>,
    private fetchFn: typeof fetch = (...a) => window.fetch(...a),
  ) {}

  // body is JSON, or a FormData sent as multipart (its boundary is the browser's).
  async request<T>(origin: string, method: string, path: string, opts: { query?: Query; body?: unknown } = {}): Promise<T> {
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
      const e = (body ?? {}) as Partial<ManagementError>
      const wait = Number(res.headers.get('Retry-After'))
      throw new ApiError(res.status, e.errorCode ?? '', e.message ?? res.statusText ?? 'Request failed', wait > 0 ? wait : undefined)
    }
    return body as T
  }

  // tenantOrigin is where a tenant's Management API answers.
  static tenantOrigin(t: Pick<SystemTenant, 'host'>): string {
    return 'https://' + t.host
  }

  getBrandingResource<T = BrandingObject>(t: SystemTenant, resource: string): Promise<T> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/' + resource)
  }
  writeBrandingResource<T = BrandingObject>(t: SystemTenant, method: 'PATCH' | 'PUT' | 'POST' | 'DELETE', resource: string, body?: unknown): Promise<T> {
    return this.request(Api.tenantOrigin(t), method, '/api/v2/' + resource, { body })
  }
  previewTenantBranding(t: SystemTenant, body: { screen: string; language: string; overrides?: BrandingObject }): Promise<BrandingPreview> {
    return this.request(this.systemOrigin, 'POST', '/api/system/tenants/' + encodeURIComponent(t.name) + '/branding/preview', { body })
  }

  getTenantSettings(t: SystemTenant): Promise<TenantSettings> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/tenants/settings')
  }
  updateTenantSettings(t: SystemTenant, body: TenantSettingsPatch): Promise<TenantSettings> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/tenants/settings', { body })
  }
  listCustomDomains(t: SystemTenant): Promise<CustomDomain[]> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/custom-domains')
  }
  createCustomDomain(t: SystemTenant, body: CustomDomainCreate): Promise<CustomDomain> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/custom-domains', { body })
  }
  getCustomDomain(t: SystemTenant, id: string): Promise<CustomDomain> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/custom-domains/' + encodeURIComponent(id))
  }
  updateCustomDomain(t: SystemTenant, id: string, body: CustomDomainUpdate): Promise<CustomDomain> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/custom-domains/' + encodeURIComponent(id), { body })
  }
  deleteCustomDomain(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/custom-domains/' + encodeURIComponent(id))
  }
  // verifyCustomDomain is never retried: only its first successful reply can
  // carry the one-time proxy key.
  verifyCustomDomain(t: SystemTenant, id: string): Promise<CustomDomainVerified> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/custom-domains/' + encodeURIComponent(id) + '/verify')
  }
  testCustomDomain(t: SystemTenant, id: string): Promise<CustomDomainTest> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/custom-domains/' + encodeURIComponent(id) + '/test')
  }
  getDefaultCustomDomain(t: SystemTenant): Promise<CustomDomain> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/custom-domains/default')
  }
  setDefaultCustomDomain(t: SystemTenant, domain: string): Promise<CustomDomain> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/custom-domains/default', { body: { domain } })
  }
  listSigningKeys(t: SystemTenant): Promise<ManagedSigningKey[]> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/keys/signing')
  }
  getSigningKey(t: SystemTenant, kid: string): Promise<ManagedSigningKey> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/keys/signing/' + encodeURIComponent(kid))
  }
  rotateSigningKeys(t: SystemTenant): Promise<ManagedSigningKey> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/keys/signing/rotate')
  }
  revokeSigningKey(t: SystemTenant, kid: string): Promise<ManagedSigningKey> {
    return this.request(Api.tenantOrigin(t), 'PUT', '/api/v2/keys/signing/' + encodeURIComponent(kid) + '/revoke')
  }
  getCustomSigningKeys(t: SystemTenant): Promise<CustomSigningJWKS> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/keys/custom-signing')
  }
  putCustomSigningKeys(t: SystemTenant, body: CustomSigningJWKS): Promise<CustomSigningJWKS> {
    return this.request(Api.tenantOrigin(t), 'PUT', '/api/v2/keys/custom-signing', { body })
  }
  deleteCustomSigningKeys(t: SystemTenant): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/keys/custom-signing')
  }
  getUserBlocks(t: SystemTenant, id: string): Promise<UserBlocks> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/user-blocks/' + encodeURIComponent(id))
  }
  deleteUserBlocks(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/user-blocks/' + encodeURIComponent(id))
  }
  getIPBlock(t: SystemTenant, ip: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/anomaly/blocks/ips/' + encodeURIComponent(ip))
  }
  deleteIPBlock(t: SystemTenant, ip: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/anomaly/blocks/ips/' + encodeURIComponent(ip))
  }
  getBruteForceProtection(t: SystemTenant): Promise<BruteForceProtection> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/attack-protection/brute-force-protection')
  }
  updateBruteForceProtection(t: SystemTenant, body: BruteForceProtectionUpdate): Promise<BruteForceProtection> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/attack-protection/brute-force-protection', { body })
  }
  getSuspiciousIpThrottling(t: SystemTenant): Promise<SuspiciousIpThrottling> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/attack-protection/suspicious-ip-throttling')
  }
  updateSuspiciousIpThrottling(t: SystemTenant, body: SuspiciousIpThrottlingUpdate): Promise<SuspiciousIpThrottling> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/attack-protection/suspicious-ip-throttling', { body })
  }
  getBreachedPasswordDetection(t: SystemTenant): Promise<BreachedPasswordDetection> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/attack-protection/breached-password-detection')
  }
  updateBreachedPasswordDetection(t: SystemTenant, body: BreachedPasswordDetectionUpdate): Promise<BreachedPasswordDetection> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/attack-protection/breached-password-detection', { body })
  }
  getBotDetection(t: SystemTenant): Promise<BotDetection> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/attack-protection/bot-detection')
  }
  updateBotDetection(t: SystemTenant, body: BotDetectionUpdate): Promise<BotDetection> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/attack-protection/bot-detection', { body })
  }
  getCaptcha(t: SystemTenant): Promise<Captcha> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/attack-protection/captcha')
  }
  updateCaptcha(t: SystemTenant, body: CaptchaUpdate): Promise<Captcha> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/attack-protection/captcha', { body })
  }

  listRoles(t: SystemTenant, q: OffsetPage & { name_filter?: string }): Promise<RolePage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/roles', { query: { ...q, include_totals: true } })
  }
  getRole(t: SystemTenant, id: string): Promise<Role> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/roles/' + encodeURIComponent(id))
  }
  createRole(t: SystemTenant, body: { name: string; description: string }): Promise<Role> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/roles', { body })
  }
  updateRole(t: SystemTenant, id: string, body: { name?: string; description?: string }): Promise<Role> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/roles/' + encodeURIComponent(id), { body })
  }
  deleteRole(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/roles/' + encodeURIComponent(id))
  }
  listRoleUsers(t: SystemTenant, id: string, q: OffsetPage): Promise<RoleUserPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/roles/' + encodeURIComponent(id) + '/users', { query: { ...q, include_totals: true } })
  }
  assignRoleUsers(t: SystemTenant, id: string, users: string[]): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/roles/' + encodeURIComponent(id) + '/users', { body: { users } })
  }
  listUserRoles(t: SystemTenant, id: string, q: OffsetPage): Promise<RolePage> {
    return this.request(Api.tenantOrigin(t), 'GET', userPath(id) + '/roles', { query: { ...q, include_totals: true } })
  }
  changeUserRoles(t: SystemTenant, id: string, method: 'POST' | 'DELETE', roles: string[]): Promise<void> {
    return this.request(Api.tenantOrigin(t), method, userPath(id) + '/roles', { body: { roles } })
  }
  listPermissions(t: SystemTenant, kind: 'roles' | 'users', id: string, q: OffsetPage): Promise<PermissionPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/' + kind + '/' + encodeURIComponent(id) + '/permissions', { query: { ...q, include_totals: true } })
  }
  changePermissions(t: SystemTenant, kind: 'roles' | 'users', id: string, method: 'POST' | 'DELETE', permissions: PermissionKey[]): Promise<void> {
    return this.request(Api.tenantOrigin(t), method, '/api/v2/' + kind + '/' + encodeURIComponent(id) + '/permissions', { body: { permissions } })
  }

  listClients(t: SystemTenant, q: { page: number; per_page: number; app_type?: string }): Promise<ClientPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/clients', { query: { ...q, include_totals: true } })
  }

  getClient(t: SystemTenant, id: string): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/clients/' + encodeURIComponent(id))
  }

  createClient(t: SystemTenant, body: ClientCreate): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/clients', { body })
  }

  updateClient(t: SystemTenant, id: string, body: ClientUpdate): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/clients/' + encodeURIComponent(id), { body })
  }

  deleteClient(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/clients/' + encodeURIComponent(id))
  }

  rotateSecret(t: SystemTenant, id: string): Promise<Client> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/clients/' + encodeURIComponent(id) + '/rotate-secret')
  }

  listResourceServers(t: SystemTenant, q: { page: number; per_page: number }): Promise<ResourceServerPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/resource-servers', { query: { ...q, include_totals: true } })
  }

  getResourceServer(t: SystemTenant, id: string): Promise<ResourceServer> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/resource-servers/' + encodeURIComponent(id))
  }

  createResourceServer(t: SystemTenant, body: ResourceServerCreate): Promise<ResourceServer> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/resource-servers', { body })
  }

  updateResourceServer(t: SystemTenant, id: string, body: ResourceServerUpdate): Promise<ResourceServer> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/resource-servers/' + encodeURIComponent(id), { body })
  }

  deleteResourceServer(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/resource-servers/' + encodeURIComponent(id))
  }

  listClientGrants(t: SystemTenant, q: { page: number; per_page: number; client_id?: string; audience?: string }): Promise<ClientGrantPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/client-grants', { query: { ...q, include_totals: true } })
  }

  createClientGrant(t: SystemTenant, body: ClientGrantCreate): Promise<ClientGrant> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/client-grants', { body })
  }

  updateClientGrant(t: SystemTenant, id: string, body: ClientGrantUpdate): Promise<ClientGrant> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/client-grants/' + encodeURIComponent(id), { body })
  }

  deleteClientGrant(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/client-grants/' + encodeURIComponent(id))
  }

  listConnections(t: SystemTenant, q: { page: number; per_page: number; strategy?: string }): Promise<ConnectionPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/connections', { query: { ...q, include_totals: true } })
  }

  // listUsers searches with Auth0's v3 query syntax; q goes out as typed.
  listUsers(t: SystemTenant, q: { q?: string; page: number; per_page: number; sort?: string; connection?: string }): Promise<UserPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/users', { query: { ...q, search_engine: 'v3', include_totals: true } })
  }

  createUser(t: SystemTenant, body: UserCreate): Promise<User> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/users', { body })
  }

  getUser(t: SystemTenant, id: string): Promise<User> {
    return this.request(Api.tenantOrigin(t), 'GET', userPath(id))
  }

  // updateUser sends only what changes. Metadata merges at the top level:
  // a key set to null is removed.
  updateUser(t: SystemTenant, id: string, body: UserUpdate): Promise<User> {
    return this.request(Api.tenantOrigin(t), 'PATCH', userPath(id), { body })
  }

  deleteUser(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', userPath(id))
  }

  // linkUser merges another database user into this one; userId is the
  // secondary's ID without its auth0| prefix.
  linkUser(t: SystemTenant, id: string, userId: string): Promise<UserIdentity[]> {
    return this.request(Api.tenantOrigin(t), 'POST', userPath(id) + '/identities', { body: { provider: 'auth0', user_id: userId } })
  }

  unlinkUser(t: SystemTenant, id: string, provider: string, userId: string): Promise<UserIdentity[]> {
    return this.request(Api.tenantOrigin(t), 'DELETE', userPath(id) + '/identities/' + encodeURIComponent(provider) + '/' + encodeURIComponent(userId))
  }

  listUserSessions(t: SystemTenant, id: string, q: { take: number; from?: string }): Promise<UserSessionPage> {
    return this.request(Api.tenantOrigin(t), 'GET', userPath(id) + '/sessions', { query: q })
  }

  deleteUserSessions(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', userPath(id) + '/sessions')
  }

  deleteSession(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/sessions/' + encodeURIComponent(id))
  }

  listUserRefreshTokens(t: SystemTenant, id: string, q: { take: number; from?: string }): Promise<UserRefreshTokenPage> {
    return this.request(Api.tenantOrigin(t), 'GET', userPath(id) + '/refresh-tokens', { query: q })
  }

  deleteUserRefreshTokens(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', userPath(id) + '/refresh-tokens')
  }

  deleteRefreshToken(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/refresh-tokens/' + encodeURIComponent(id))
  }

  listUserGrants(t: SystemTenant, userId: string): Promise<UserGrant[]> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/grants', { query: { user_id: userId } })
  }

  deleteGrant(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/grants/' + encodeURIComponent(id))
  }

  // The ticket functions return a single-use URL. Callers show it once and
  // must not keep it anywhere but the component that shows it.
  createPasswordChangeTicket(t: SystemTenant, userId: string): Promise<{ ticket: string }> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/tickets/password-change', { body: { user_id: userId } })
  }

  createVerificationTicket(t: SystemTenant, userId: string): Promise<{ ticket: string }> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/tickets/email-verification', { body: { user_id: userId } })
  }

  // The jobs. The list is the system API's (Auth0 has none); the rest are
  // the tenant's /api/v2/jobs.
  listJobs(t: Pick<SystemTenant, 'name'>, q: { page: number; per_page: number }): Promise<JobPage> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/jobs`, { query: { ...q, include_totals: true } })
  }

  createImportJob(t: SystemTenant, form: FormData): Promise<Job> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/jobs/users-imports', { body: form })
  }

  createExportJob(t: SystemTenant, body: UsersExportJobCreate): Promise<Job> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/jobs/users-exports', { body })
  }

  // getJob reads the job; a completed export carries a new 60-second
  // location on every read, so callers read again for each download.
  getJob(t: SystemTenant, id: string): Promise<Job> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/jobs/' + encodeURIComponent(id))
  }

  // getJobErrors: the import's failed records (secrets masked by the
  // server), undefined for an export (204), or the job itself when it failed.
  getJobErrors(t: SystemTenant, id: string): Promise<JobError[] | Job | undefined> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/jobs/' + encodeURIComponent(id) + '/errors')
  }

  createVerificationEmailJob(t: SystemTenant, userId: string): Promise<Job> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/jobs/verification-email', { body: { user_id: userId } })
  }

  getEmailProvider(t: SystemTenant): Promise<EmailProvider> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/emails/provider')
  }

  createEmailProvider(t: SystemTenant, body: EmailProviderWrite): Promise<EmailProvider> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/emails/provider', { body })
  }

  updateEmailProvider(t: SystemTenant, body: EmailProviderWrite): Promise<EmailProvider> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/emails/provider', { body })
  }

  deleteEmailProvider(t: SystemTenant): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/emails/provider')
  }

  getEmailTemplate(t: SystemTenant, name: EmailTemplateName): Promise<EmailTemplate> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/email-templates/' + encodeURIComponent(name))
  }

  createEmailTemplate(t: SystemTenant, body: EmailTemplate): Promise<EmailTemplate> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/email-templates', { body })
  }

  putEmailTemplate(t: SystemTenant, name: EmailTemplateName, body: EmailTemplate): Promise<EmailTemplate> {
    return this.request(Api.tenantOrigin(t), 'PUT', '/api/v2/email-templates/' + encodeURIComponent(name), { body })
  }

  previewTenantEmail(t: Pick<SystemTenant, 'name'>, body: { template: EmailTemplateName; overrides?: Record<string, unknown> }): Promise<EmailPreview> {
    return this.request(this.systemOrigin, 'POST', `/api/system/tenants/${encodeURIComponent(t.name)}/emails/preview`, { body })
  }

  testTenantEmail(t: Pick<SystemTenant, 'name'>, body: { template: EmailTemplateName }): Promise<void | { status: string; reason?: string; execution_id?: string }> {
    return this.request(this.systemOrigin, 'POST', `/api/system/tenants/${encodeURIComponent(t.name)}/emails/test`, { body })
  }

  getConnection(t: SystemTenant, id: string): Promise<Connection> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/connections/' + encodeURIComponent(id))
  }

  createConnection(t: SystemTenant, body: ConnectionCreate): Promise<Connection> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/connections', { body })
  }

  updateConnection(t: SystemTenant, id: string, body: ConnectionUpdate): Promise<Connection> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/connections/' + encodeURIComponent(id), { body })
  }

  deleteConnection(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/connections/' + encodeURIComponent(id))
  }

  // Enabled applications are read and changed only through the clients
  // endpoint, never through enabled_clients on PATCH.
  getConnectionClients(t: SystemTenant, id: string, q: { take: number; from?: string }): Promise<{ clients: { client_id: string }[]; next?: string }> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/connections/' + encodeURIComponent(id) + '/clients', { query: q })
  }

  updateConnectionClients(t: SystemTenant, id: string, body: ConnectionClientStatus[]): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/connections/' + encodeURIComponent(id) + '/clients', { body })
  }

  // tryScript runs one custom database script with test arguments (system
  // API). The answer is for the page only; callers must not keep it.
  tryScript(t: Pick<SystemTenant, 'name'>, id: string, script: string, args: unknown[]): Promise<ScriptTryResult> {
    const path = `/api/system/tenants/${encodeURIComponent(t.name)}/connections/${encodeURIComponent(id)}/scripts/${encodeURIComponent(script)}/try`
    return this.request(this.systemOrigin, 'POST', path, { body: { args } })
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
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/modules', { query: q })
  }

  createActionModule(t: SystemTenant, body: ActionModuleCreate): Promise<ActionModule> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/actions/modules', { body })
  }

  getActionModule(t: SystemTenant, id: string): Promise<ActionModule> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id))
  }

  updateActionModule(t: SystemTenant, id: string, body: ActionModuleUpdate): Promise<ActionModule> {
    return this.request(Api.tenantOrigin(t), 'PATCH', '/api/v2/actions/modules/' + encodeURIComponent(id), { body })
  }

  deleteActionModule(t: SystemTenant, id: string): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', '/api/v2/actions/modules/' + encodeURIComponent(id))
  }

  listActionModuleVersions(t: SystemTenant, id: string, q: { page: number; per_page: number }): Promise<ActionModuleVersionsPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/versions', { query: q })
  }

  getActionModuleVersion(t: SystemTenant, id: string, versionId: string): Promise<ActionModuleVersion> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/versions/' + encodeURIComponent(versionId))
  }

  publishActionModule(t: SystemTenant, id: string): Promise<ActionModuleVersion> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/versions')
  }

  rollbackActionModule(t: SystemTenant, id: string, body: { module_version_id: string }): Promise<ActionModule> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/rollback', { body })
  }

  listActionModuleActions(t: SystemTenant, id: string, q: { page: number; per_page: number }): Promise<ActionModuleActionsPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/modules/' + encodeURIComponent(id) + '/actions', { query: q })
  }

  listActions(t: SystemTenant, q: { page: number; per_page: number; triggerId?: string; actionName?: string; deployed?: boolean }): Promise<ActionsPage> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/actions', { query: q })
  }

  createAction(t: SystemTenant, body: ActionCreate): Promise<Action> {
    return this.request(Api.tenantOrigin(t), 'POST', '/api/v2/actions/actions', { body })
  }

  getAction(t: SystemTenant, id: string): Promise<Action> {
    return this.request(Api.tenantOrigin(t), 'GET', actionPath(id))
  }

  updateAction(t: SystemTenant, id: string, body: ActionUpdate): Promise<Action> {
    return this.request(Api.tenantOrigin(t), 'PATCH', actionPath(id), { body })
  }

  deleteAction(t: SystemTenant, id: string, force = false): Promise<void> {
    return this.request(Api.tenantOrigin(t), 'DELETE', actionPath(id), { query: { force } })
  }

  deployAction(t: SystemTenant, id: string): Promise<ActionVersion> {
    return this.request(Api.tenantOrigin(t), 'POST', actionPath(id) + '/deploy')
  }

  listActionVersions(t: SystemTenant, id: string, q: { page: number; per_page: number }): Promise<ActionVersionsPage> {
    return this.request(Api.tenantOrigin(t), 'GET', actionPath(id) + '/versions', { query: q })
  }

  getActionVersion(t: SystemTenant, id: string, versionId: string): Promise<ActionVersion> {
    return this.request(Api.tenantOrigin(t), 'GET', actionPath(id) + '/versions/' + encodeURIComponent(versionId))
  }

  deployActionVersion(t: SystemTenant, id: string, versionId: string): Promise<ActionVersion> {
    return this.request(Api.tenantOrigin(t), 'POST', actionPath(id) + '/versions/' + encodeURIComponent(versionId) + '/deploy', { body: { update_draft: false } })
  }

  testAction(t: SystemTenant, id: string, body: ActionTestRequest): Promise<ActionTestResponse> {
    return this.request(Api.tenantOrigin(t), 'POST', actionPath(id) + '/test', { body })
  }

  listActionTriggers(t: SystemTenant): Promise<ActionTriggers> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/triggers')
  }

  listActionBindings(t: SystemTenant, trigger: string, q: { page: number; per_page: number }): Promise<ActionBindingsPage> {
    return this.request(Api.tenantOrigin(t), 'GET', triggerPath(trigger), { query: q })
  }

  updateActionBindings(t: SystemTenant, trigger: string, bindings: ActionBindingInput[]): Promise<ActionBindings> {
    return this.request(Api.tenantOrigin(t), 'PATCH', triggerPath(trigger), { body: { bindings } })
  }

  getActionExecutionAttempt(t: SystemTenant, id: string): Promise<void | { job_id: string; attempt: number }> {
    return this.request(this.systemOrigin, 'GET', `/api/system/tenants/${encodeURIComponent(t.name)}/actions/executions/${encodeURIComponent(id)}/attempt`)
  }

  getActionExecution(t: SystemTenant, id: string): Promise<ActionExecution> {
    return this.request(Api.tenantOrigin(t), 'GET', '/api/v2/actions/executions/' + encodeURIComponent(id))
  }

  async allActions(t: SystemTenant, triggerId?: string): Promise<Action[]> {
    return collect(page => this.listActions(t, { page, per_page: ALL_PER_PAGE, triggerId }).then(r => ({ items: r.actions, total: r.total })))
  }

  async allActionBindings(t: SystemTenant, trigger: string): Promise<ActionBinding[]> {
    return collect(page => this.listActionBindings(t, trigger, { page, per_page: ALL_PER_PAGE }).then(r => ({ items: r.bindings, total: r.total })))
  }

  listTenants(): Promise<SystemTenant[]> {
    return this.request(this.systemOrigin, 'GET', '/api/system/tenants')
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

function actionPath(id: string): string { return '/api/v2/actions/actions/' + encodeURIComponent(id) }
function triggerPath(id: string): string { return '/api/v2/actions/triggers/' + encodeURIComponent(id) + '/bindings' }
