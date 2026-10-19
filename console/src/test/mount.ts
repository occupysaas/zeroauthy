import { flushPromises, mount } from '@vue/test-utils'
import type { Component } from 'vue'
import { servicesKey } from '../context'
import { useTenantsStore } from '../stores/tenants'
import type { SystemTenant } from '../api/client'
import { fakeServices, memoryRouter, tenant, type Call, type Reply } from './services'

// mountAt mounts page at path, signed in, with the API answered by handler
// (the tenant list included).
export async function mountAt(page: Component, path: string, handler: (c: Call) => Reply | Promise<Reply>, tenantExtra: Partial<SystemTenant> = {}) {
  const { services, calls, pinia, i18n } = fakeServices((c) =>
    c.url.endsWith('/api/system/tenants') ? { status: 200, body: [tenant('acme', tenantExtra), tenant('system', { reserved: true })] } : handler(c),
  )
  await useTenantsStore().load(services.api)
  calls.length = 0 // keep only the page's own calls
  const router = memoryRouter()
  await router.push(path)
  const wrapper = mount(page, {
    attachTo: document.body,
    global: { plugins: [router, pinia, i18n], provide: { [servicesKey as symbol]: services } },
  })
  await flushPromises()
  return { wrapper, router, calls }
}

export function apiError(status: number, errorCode: string, message: string) {
  return { status, body: { statusCode: status, error: 'Error', errorCode, message } }
}
