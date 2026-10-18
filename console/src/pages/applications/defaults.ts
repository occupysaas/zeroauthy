import type { AppType, ClientCreate } from '../../api/client'

// The settings the console gives a new application of each type. The
// Management API applies the same defaults to every type (D-0039), so the
// console sends per-type ones, as Auth0's dashboard does.
export function defaultsFor(type: AppType): Omit<ClientCreate, 'name'> {
  switch (type) {
    case 'spa':
    case 'native':
      return { app_type: type, token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'] }
    case 'regular_web':
      return {
        app_type: type,
        token_endpoint_auth_method: 'client_secret_post',
        grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
      }
    case 'non_interactive':
      return { app_type: type, token_endpoint_auth_method: 'client_secret_post', grant_types: ['client_credentials'] }
  }
}

export const appTypes: AppType[] = ['native', 'spa', 'regular_web', 'non_interactive']

// lines splits a textarea into its non-empty lines.
export function lines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

// fieldErrors assigns each part of an invalid_body message to the field it
// names; the rest is general.
export function fieldErrors(message: string, fields: Record<string, string[]>): { byField: Record<string, string>; general: string } {
  const byField: Record<string, string> = {}
  const rest: string[] = []
  const parts = message.replace(/^Payload validation error:\s*/, '').split('; ')
  for (const part of parts) {
    const field = Object.keys(fields).find((f) => fields[f]!.some((k) => part.includes(k)))
    if (field) byField[field] = byField[field] ? byField[field] + '; ' + part : part
    else rest.push(part)
  }
  return { byField, general: rest.join('; ') }
}
