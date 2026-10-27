import type { Connection, SystemTenant } from '../../../api/client'

// Classification and route support are distinct: historical social routes
// must continue opening generic OIDC connections.
export const federatedStrategies = ['google-oauth2', 'oauth2', 'oidc', 'windowslive', 'waad'] as const
export const socialStrategies = ['google-oauth2', 'oauth2', 'windowslive'] as const
export const enterpriseStrategies = ['oidc', 'waad'] as const
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
export function callbackURLs(t: SystemTenant): string[] {
  const hosts = [t.host, ...(t.domains ?? [])].filter((h): h is string => !!h)
  return [...new Set(hosts)].map((h) => `https://${h}/login/callback`)
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
