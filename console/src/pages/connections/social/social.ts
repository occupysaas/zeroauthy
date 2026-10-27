import type { Connection, SystemTenant } from '../../../api/client'

// The federated strategies this console manages (Plan 24). OIDC is an
// enterprise connection shown here with an explicit supported-subset label.
export const socialStrategies = ['google-oauth2', 'oauth2', 'oidc'] as const
export type SocialStrategy = (typeof socialStrategies)[number]

export function isSocial(c: Pick<Connection, 'strategy'>): boolean {
  return (socialStrategies as readonly string[]).includes(c.strategy ?? '')
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
