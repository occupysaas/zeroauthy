import type { Connection, SystemTenant } from '../../../api/client'

// Classification and route support are distinct: historical social routes
// must continue opening generic OIDC connections.
export const federatedStrategies = ['google-oauth2', 'oauth2', 'oidc', 'windowslive', 'waad', 'apple', 'github', 'okta', 'samlp', 'adfs', 'google-apps', 'ad'] as const
export const socialStrategies = ['google-oauth2', 'oauth2', 'windowslive', 'apple', 'github'] as const
export const enterpriseStrategies = ['oidc', 'okta', 'waad', 'samlp', 'adfs', 'google-apps', 'ad'] as const
export type FederatedStrategy = (typeof federatedStrategies)[number]
export type SocialStrategy = (typeof socialStrategies)[number]
export type EnterpriseStrategy = (typeof enterpriseStrategies)[number]

export function isFederated(c: Pick<Connection, 'strategy'>): boolean {
  return (federatedStrategies as readonly string[]).includes(c.strategy ?? '')
}

/** Compatibility alias for the historical federated route detector. */
export const isSocial = isFederated

export function isSocialConnection(c: Pick<Connection, 'strategy'>): boolean {
  return (socialStrategies as readonly string[]).includes(c.strategy ?? '')
}

export function isEnterpriseConnection(c: Pick<Connection, 'strategy'>): boolean {
  return (enterpriseStrategies as readonly string[]).includes(c.strategy ?? '')
}

export function connectionRoute(c: Pick<Connection, 'strategy'>): string {
  return isEnterpriseConnection(c) ? 'enterprise-connection' : isFederated(c) ? 'social-connection' : 'connection'
}

export const MICROSOFT_GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

/** Mirrors the Microsoft single-directory authority contract, without trimming
 * whitespace into a different accepted identifier. */
export function microsoftTenant(value: string): string | undefined {
  const tenant = value.toLowerCase()
  if (!tenant || tenant.length > 253 || ['common', 'organizations', 'consumers', '9188040d-6c67-4c5b-b112-36a304b66dad'].includes(tenant)) return
  if (MICROSOFT_GUID.test(tenant) || tenant.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return tenant
}

/** The connection name rule shared with the database connections page. */
export const NAME = /^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$/

/** The limit of a fetchUserProfile script, in UTF-8 bytes. */
export const MAX_SCRIPT_BYTES = 65536

export function utf8Bytes(s: string): number {
  return new TextEncoder().encode(s).length
}

/** Absolute https URL without credentials or a fragment. */
export function httpsURL(s: string): boolean {
  try {
    const u = new URL(s)
    return u.protocol === 'https:' && u.hostname !== '' && u.username === '' && u.password === '' && u.hash === '' && !s.includes('#')
  } catch {
    return false
  }
}

/** The provider callback URLs to register: the canonical host and every
 * custom domain the tenant answers on, each with /login/callback. */
export function callbackURLs(t: SystemTenant, strategy?: string): string[] {
  const hosts = [...new Set([t.host, ...(t.domains ?? [])].filter((h): h is string => !!h))]
  const out = hosts.map((h) => `https://${h}/login/callback`)
  // Google Workspace directory provisioning consent (Plan 37c, LR37c-15).
  if (strategy === 'google-apps') out.push(...hosts.map((h) => `https://${h}/directory-provisioning/callback`))
  return out
}

export const defaultScript = `function fetchUserProfile(accessToken, context, callback) {
  request.get({ url: 'https://provider.example/userinfo', headers: { Authorization: 'Bearer ' + accessToken }, json: true }, function (err, response, body) {
    if (err || response.statusCode !== 200) return callback(err || new Error('profile request failed'))
    callback(null, { user_id: String(body.id), email: body.email, name: body.name })
  })
}
`

export type Options = Record<string, unknown>

export function optionsOf(c: Connection): Options {
  return (c.options ?? {}) as Options
}

/** A local PEM/PKCS#8 envelope check; the server validates the EC private key. */
export function applePEM(value: string): boolean {
  const match = /^\s*-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)\s+-----END PRIVATE KEY-----\s*$/.exec(value)
  if (!match) return false
  try {
    const der = atob(match[1]!.replace(/\s/g, ''))
    return der.charCodeAt(0) === 0x30 && der.includes('\x06\x07\x2a\x86\x48\xce\x3d\x02\x01') && der.includes('\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07')
  } catch { return false }
}

export const APPLE_IDENTIFIER = /^[A-Z0-9]{10}$/

/** GitHub scope flags in inventory order (internal/federation/rules/github.go
 * GitHubScopeFlags); `email` and `profile` are separate options. */
export const githubScopeFlags = [
  { option: 'admin_org', scope: 'admin:org' },
  { option: 'admin_public_key', scope: 'admin:public_key' },
  { option: 'admin_repo_hook', scope: 'admin:repo_hook' },
  { option: 'delete_repo', scope: 'delete_repo' },
  { option: 'follow', scope: 'user:follow' },
  { option: 'gist', scope: 'gist' },
  { option: 'notifications', scope: 'notifications' },
  { option: 'public_repo', scope: 'public_repo' },
  { option: 'read_org', scope: 'read:org' },
  { option: 'read_public_key', scope: 'read:public_key' },
  { option: 'read_repo_hook', scope: 'read:repo_hook' },
  { option: 'read_user', scope: 'read:user' },
  { option: 'repo', scope: 'repo' },
  { option: 'repo_deployment', scope: 'repo_deployment' },
  { option: 'repo_status', scope: 'repo:status' },
  { option: 'write_org', scope: 'write:org' },
  { option: 'write_public_key', scope: 'write:public_key' },
  { option: 'write_repo_hook', scope: 'write:repo_hook' },
] as const

/** The scope a GitHub connection requests: user:email when email is on, then
 * the checked flags, space-separated. Empty is valid. */
export function githubScope(email: boolean, flags: Record<string, boolean>): string {
  const scopes: string[] = email ? ['user:email'] : []
  for (const f of githubScopeFlags) if (flags[f.option] === true && !scopes.includes(f.scope)) scopes.push(f.scope)
  return scopes.join(' ')
}

/** The checked flags of a stored connection's options. */
export function githubFlagsOf(o: Options): Record<string, boolean> {
  return Object.fromEntries(githubScopeFlags.map((f) => [f.option, o[f.option] === true]))
}

/** The options a GitHub form writes: only checked flags, never `scope`. */
export function githubFlagOptions(email: boolean, flags: Record<string, boolean>): Options {
  const out: Options = { email }
  for (const f of githubScopeFlags) if (flags[f.option] === true) out[f.option] = true
  return out
}

/** The ADFS relying party endpoint and identifier (Plan 37b). */
export function adfsCallback(t: SystemTenant): string {
  return `https://${t.host}/login/callback`
}
export function adfsRealm(t: SystemTenant, connection: string, entityId?: unknown): string {
  return typeof entityId === 'string' && entityId !== '' ? entityId : `urn:auth0:${t.name}:${connection}`
}

/** The SAML ACS of a samlp connection (Plan 37a). */
export function samlACS(t: SystemTenant, connection: string): string {
  return `https://${t.host}/login/callback?connection=${encodeURIComponent(connection)}`
}

/** A PEM certificate or base64 DER, as the samlp rules accept. */
export function samlCertificate(raw: string): boolean {
  const s = raw.trim()
  if (s.startsWith('-----BEGIN CERTIFICATE-----')) return /-----END CERTIFICATE-----$/.test(s)
  return s.length > 64 && /^[A-Za-z0-9+/=\s]+$/.test(s)
}
