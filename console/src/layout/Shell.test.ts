import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { servicesKey } from '../context'
import { useTenantsStore } from '../stores/tenants'
import { fakeServices, memoryRouter, tenant } from '../test/services'
import Shell from './Shell.vue'

async function mountShell(path: string) {
  const { services, pinia, i18n } = fakeServices((c) =>
    c.url.endsWith('/api/system/tenants') ? { status: 200, body: [tenant('acme'), tenant('system', { reserved: true })] } : { status: 404 },
  )
  await useTenantsStore().load(services.api)
  const router = memoryRouter()
  await router.push(path)
  const wrapper = mount(Shell, { attachTo: document.body, global: { plugins: [router, pinia, i18n], provide: { [servicesKey as symbol]: services } } })
  await flushPromises()
  return { wrapper, router }
}

const nav = 'nav[aria-label="Sections"]'

// Link texts without the Planned tag: the label is the link's first span.
async function sidebar(path: string): Promise<{ links: string[]; groups: string[] }> {
  const { wrapper } = await mountShell(path)
  const links = wrapper.findAll(`${nav} a:not([target])`).map((a) => a.get('span').text())
  const groups = wrapper.findAll(`${nav} h2`).map((h) => h.text())
  wrapper.unmount()
  return { links, groups }
}

const common = ['Home', 'Applications', 'APIs', 'Database', 'Social', 'Users', 'Roles', 'Organizations', 'Attack protection', 'Multi-factor', 'Actions', 'Universal Login', 'Email templates', 'Custom domains', 'Logs', 'Tenant settings']
const groups = ['Applications', 'Authentication', 'User management', 'Security', 'Actions', 'Branding', 'Monitoring', 'Settings']

describe('Shell sidebar', () => {
  it('lists Operators only on the system tenant', async () => {
    expect((await sidebar('/t/acme/')).links).toEqual(common)
    expect((await sidebar('/t/system/')).links).toEqual([...common, 'Operators'])
  })

  it('groups the sections under headings', async () => {
    expect((await sidebar('/t/acme/')).groups).toEqual(groups)
    expect((await sidebar('/t/system/')).groups).toEqual([...groups, 'System'])
  })

  it('tags planned sections and not live ones', async () => {
    const { wrapper } = await mountShell('/t/acme/')
    const link = (name: string) => wrapper.findAll(`${nav} a:not([target])`).find((a) => a.get('span').text() === name)!
    expect(link('Social').attributes('title')).toMatch(/^slice 6: /)
    expect(link('Users').text()).not.toContain('Planned')
    expect(link('Roles').attributes('title')).toBe('later: /api/v2/roles')
    expect(link('Applications').text()).not.toContain('Planned')
    wrapper.unmount()
  })
})

describe('Shell tenant switching', () => {
  it('shows Operators only while on the system tenant, without a remount', async () => {
    const { wrapper, router } = await mountShell('/t/acme/')
    const labels = () => wrapper.findAll(`${nav} a:not([target])`).map((a) => a.get('span').text())
    expect(labels()).not.toContain('Operators')
    await router.push('/t/system/')
    await flushPromises()
    expect(labels()).toContain('Operators')
    await router.push('/t/acme/')
    await flushPromises()
    expect(labels()).not.toContain('Operators')
    wrapper.unmount()
  })
})

describe('Shell menu drawer', () => {
  it('carries the Docs and Source links for narrow screens', async () => {
    const { wrapper } = await mountShell('/t/acme/')
    expect(wrapper.findAll(`${nav} a[target]`).map((a) => a.text())).toEqual(['Docs', 'Source'])
    wrapper.unmount()
  })


  it('toggles, closes on Escape returning focus, and closes on navigation', async () => {
    const { wrapper, router } = await mountShell('/t/acme/')
    const button = wrapper.get('button[aria-controls]')
    expect(button.text()).toBe('Menu')
    expect(button.attributes('aria-expanded')).toBe('false')

    await button.trigger('click')
    await flushPromises()
    expect(button.attributes('aria-expanded')).toBe('true')
    expect(document.activeElement).toBe(wrapper.get(`${nav} a`).element)

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await flushPromises()
    expect(button.attributes('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(button.element)

    await button.trigger('click')
    await flushPromises()
    const handled = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    handled.preventDefault()
    document.dispatchEvent(handled)
    await flushPromises()
    expect(button.attributes('aria-expanded')).toBe('true')

    await router.push('/t/acme/applications')
    await flushPromises()
    expect(button.attributes('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(button.element)
    wrapper.unmount()
  })
})
