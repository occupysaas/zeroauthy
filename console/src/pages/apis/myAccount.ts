import type { ResourceServer, SystemTenant } from '../../api/client'

// The My Account API (Plan 42a) is the system API https://{canonical host}/me/:
// the tenant's Management API identifier with /me/ in place of /api/v2/.
export function myAccountIdentifier(t: SystemTenant): string {
  const m = t.management_api_identifier ?? ''
  return m.endsWith('/api/v2/') ? m.slice(0, -'/api/v2/'.length) + '/me/' : ''
}

export function isMyAccount(t: SystemTenant, s: ResourceServer): boolean {
  const id = myAccountIdentifier(t)
  return !!s.is_system && id !== '' && s.identifier === id
}

// The My Organization API (Plan 42b): https://{canonical host}/my-org/.
export function myOrgIdentifier(t: SystemTenant): string {
  const m = t.management_api_identifier ?? ''
  return m.endsWith('/api/v2/') ? m.slice(0, -'/api/v2/'.length) + '/my-org/' : ''
}

export function isMyOrg(t: SystemTenant, s: ResourceServer): boolean {
  const id = myOrgIdentifier(t)
  return !!s.is_system && id !== '' && s.identifier === id
}
