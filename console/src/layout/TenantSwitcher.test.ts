import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { servicesKey } from '../context'
import { useTenantsStore } from '../stores/tenants'
import { fakeServices, memoryRouter, tenant } from '../test/services'
import TenantSwitcher from './TenantSwitcher.vue'

enableAutoUnmount(afterEach)

async function setup(handler: Parameters<typeof fakeServices>[0]) {
  const { services, calls, pinia, i18n } = fakeServices(handler)
  await useTenantsStore().load(services.api)
  const router = memoryRouter()
  await router.push('/t/acme/applications')
  const wrapper = mount(TenantSwitcher, {
    attachTo: document.body,
    global: { plugins: [router, pinia, i18n], provide: { [servicesKey as symbol]: services } },
  })
  return { wrapper, router, calls, services }
}

async function openMenu(wrapper: Awaited<ReturnType<typeof setup>>['wrapper']) {
  const trigger = wrapper.find('button')
  await trigger.trigger('keydown', { key: 'Enter' })
  await flushPromises()
}

function items(): HTMLElement[] {
  return Array.from(document.body.querySelectorAll<HTMLElement>('[role="menuitem"]'))
}

describe('TenantSwitcher', () => {
  it('lists the tenants and switches, keeping the section', async () => {
    const { wrapper, router } = await setup((c) =>
      c.url.endsWith('/api/console/tenants') ? { status: 200, body: [tenant('acme'), tenant('globex'), tenant('system', { reserved: true })] } : { status: 404 },
    )
    expect(wrapper.text()).toContain('acme')
    await openMenu(wrapper)
    const labels = items().map((i) => i.textContent?.trim() ?? '')
    expect(labels.some((l) => l.startsWith('globex'))).toBe(true)
    expect(labels.some((l) => l.includes('Create tenant'))).toBe(true)
    items()
      .find((i) => i.textContent?.trim().startsWith('globex'))!
      .click()
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/t/globex/applications')
    wrapper.unmount()
  })

  it('lists only allowed tenants and hides tenant creation without system access', async () => {
    const { wrapper } = await setup(() => ({ status: 200, body: [tenant('acme')] }))
    await openMenu(wrapper)
    const labels = items().map((item) => item.textContent?.trim())
    expect(labels).toEqual(['acme(current)'])
    wrapper.unmount()
  })

  it('refreshes allowed tenants after a Management API 403', async () => {
    let removed = false
    const { wrapper, services, calls } = await setup((call) => {
      if (new URL(call.url).pathname.endsWith('/clients')) {
        removed = true
        return { status: 403, body: { errorCode: 'insufficient_scope', message: 'Access removed' } }
      }
      return { status: 200, body: removed ? [tenant('globex')] : [tenant('acme'), tenant('globex')] }
    })
    await expect(services.api.listClients(tenant('acme'), { page: 0, per_page: 10 })).rejects.toMatchObject({ status: 403 })
    await flushPromises()
    await openMenu(wrapper)
    expect(items().some((item) => item.textContent?.includes('acme'))).toBe(false)
    expect(items().some((item) => item.textContent?.includes('globex'))).toBe(true)
    expect(calls.filter((call) => call.url.endsWith('/api/console/tenants'))).toHaveLength(2)
    wrapper.unmount()
  })

  it('clears stale tenants when the refresh after a 403 fails', async () => {
    let removed = false
    const { wrapper, services } = await setup((call) => {
      if (new URL(call.url).pathname.endsWith('/clients')) {
        removed = true
        return { status: 403, body: { message: 'Access removed' } }
      }
      return removed
        ? { status: 503, body: { message: 'Discovery unavailable' } }
        : { status: 200, body: [tenant('acme')] }
    })
    await expect(services.api.listClients(tenant('acme'), { page: 0, per_page: 10 })).rejects.toMatchObject({ status: 403 })
    await openMenu(wrapper)
    expect(items()).toHaveLength(0)
    expect(document.body.textContent).toContain('Discovery unavailable')
  })

  it('creates a tenant and opens it', async () => {
    const { wrapper, router, calls } = await setup((c) => {
      if (c.method === 'POST') return { status: 201, body: tenant('initech', { domains: ['login.initech.test'] }) }
      return { status: 200, body: [tenant('acme'), tenant('system', { reserved: true })] }
    })
    await openMenu(wrapper)
    items()
      .find((i) => i.textContent?.includes('Create tenant'))!
      .click()
    await flushPromises()
    const name = document.body.querySelector<HTMLInputElement>('#tenant-name')!
    const domains = document.body.querySelector<HTMLTextAreaElement>('#tenant-domains')!
    name.value = 'initech'
    name.dispatchEvent(new Event('input'))
    domains.value = 'login.initech.test'
    domains.dispatchEvent(new Event('input'))
    document.body.querySelector<HTMLFormElement>('form')!.dispatchEvent(new Event('submit'))
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('https://admin.example.test/api/system/tenants')
    expect(post.body).toEqual({ name: 'initech', domains: ['login.initech.test'] })
    expect(router.currentRoute.value.fullPath).toBe('/t/initech/')
    wrapper.unmount()
  })

  it('shows the API error when creation fails', async () => {
    const { wrapper, router } = await setup((c) => {
      if (c.method === 'POST') return { status: 409, body: { statusCode: 409, error: 'Conflict', message: 'a tenant named "acme" exists', errorCode: 'conflict' } }
      return { status: 200, body: [tenant('acme'), tenant('system', { reserved: true })] }
    })
    await openMenu(wrapper)
    items()
      .find((i) => i.textContent?.includes('Create tenant'))!
      .click()
    await flushPromises()
    const name = document.body.querySelector<HTMLInputElement>('#tenant-name')!
    name.value = 'acme'
    name.dispatchEvent(new Event('input'))
    document.body.querySelector<HTMLFormElement>('form')!.dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(document.body.querySelector('[role="alert"]')?.textContent).toContain('a tenant named "acme" exists')
    expect(router.currentRoute.value.fullPath).toBe('/t/acme/applications')
    wrapper.unmount()
  })

  it('reports a tenant list that cannot load', async () => {
    const { wrapper } = await setup(() => ({ status: 500, body: { statusCode: 500, error: 'Internal Server Error', message: 'Internal error' } }))
    await openMenu(wrapper)
    expect(document.body.textContent).toContain('Internal error')
    wrapper.unmount()
  })
})
