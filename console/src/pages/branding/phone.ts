import { Api, type SystemTenant } from '../../api/client'
import type { components } from '../../api/schema'
export type PhoneProvider = components['schemas']['PhoneProvider']
export type ProviderWrite = components['schemas']['PhoneProviderCreate']
export type PhoneTemplate = components['schemas']['PhoneTemplate']
export const providerResource = 'branding/phone/providers'
export const templateResource = 'branding/phone/templates'
export const resourceId = (resource: string, id: string) => resource + '/' + encodeURIComponent(id)
export async function providers(api: Api, tenant: SystemTenant): Promise<PhoneProvider[]> {
  const result = await api.getBrandingResource<{ providers?: PhoneProvider[] }>(tenant, providerResource)
  // Explicit public projection also protects against accidentally changed API responses.
  return (result.providers ?? []).map(({ id, name, disabled, configuration }) => ({
    id,
    name,
    disabled,
    configuration,
  }))
}
export function tryPhone(
  api: Api,
  tenant: SystemTenant,
  resource: string,
  to: string,
  delivery_method: 'text' | 'voice'
) {
  return api.request(Api.tenantOrigin(tenant), 'POST', '/api/v2/' + resource + '/try', {
    body: { to, delivery_method },
  })
}
