import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { client, connection, type Call } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/m1'
const body = () => document.body

function tabTo(name: string) {
  const trigger = Array.from(body().querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}

function backend(enabled: Record<string, string[]>, listFails = false) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/clients/m1') return { status: 200, body: client('m1', { name: 'Billing' }) }
    if (u.pathname === '/api/v2/connections') {
      if (listFails) return apiError(500, 'internal_error', 'Internal error')
      const list = Object.keys(enabled).map((id) => connection(id, { name: 'Conn ' + id }))
      return { status: 200, body: { connections: list, start: 0, limit: 100, total: list.length } }
    }
    const m = /^\/api\/v2\/connections\/(.+)\/clients$/.exec(u.pathname)
    if (m && c.method === 'GET') return { status: 200, body: { clients: enabled[m[1]!]!.map((client_id) => ({ client_id })) } }
    if (m && c.method === 'PATCH') {
      for (const e of c.body as { client_id: string; status: boolean }[]) {
        enabled[m[1]!] = e.status ? [...enabled[m[1]!]!, e.client_id] : enabled[m[1]!]!.filter((x) => x !== e.client_id)
      }
      return { status: 204 }
    }
    return { status: 404 }
  }
}

describe('Application connections tab', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('shows a switch per connection, on where this application is enabled', async () => {
    const { wrapper } = await mountAt(Detail, path, backend({ c1: ['m1'], c2: [] }))
    tabTo('Connections')
    await flushPromises()
    expect(body().querySelector<HTMLInputElement>('input[aria-label="Enable Conn c1 for this application"]')!.checked).toBe(true)
    expect(body().querySelector<HTMLInputElement>('input[aria-label="Enable Conn c2 for this application"]')!.checked).toBe(false)
    wrapper.unmount()
  })

  it('enables and disables through the clients endpoint', async () => {
    const state = { c1: ['m1'], c2: [] as string[] }
    const { wrapper, calls } = await mountAt(Detail, path, backend(state))
    tabTo('Connections')
    await flushPromises()
    const on = body().querySelector<HTMLInputElement>('input[aria-label="Enable Conn c2 for this application"]')!
    on.checked = true
    on.dispatchEvent(new Event('change'))
    await flushPromises()
    const off = body().querySelector<HTMLInputElement>('input[aria-label="Enable Conn c1 for this application"]')!
    off.checked = false
    off.dispatchEvent(new Event('change'))
    await flushPromises()
    const patches = calls.filter((c) => c.method === 'PATCH')
    expect(patches.map((c) => [new URL(c.url).pathname, c.body])).toEqual([
      ['/api/v2/connections/c2/clients', [{ client_id: 'm1', status: true }]],
      ['/api/v2/connections/c1/clients', [{ client_id: 'm1', status: false }]],
    ])
    expect(state).toEqual({ c1: [], c2: ['m1'] })
    wrapper.unmount()
  })

  it('shows an empty state, and an error with a retry', async () => {
    const empty = await mountAt(Detail, path, backend({}))
    tabTo('Connections')
    await flushPromises()
    expect(body().textContent).toContain('no connections yet')
    empty.wrapper.unmount()
    document.body.innerHTML = ''
    const bad = await mountAt(Detail, path, backend({}, true))
    tabTo('Connections')
    await flushPromises()
    expect(body().querySelector('[role="alert"]')!.textContent).toContain('Internal error')
    bad.wrapper.unmount()
  })
})


describe('Federated application enablement', () => {
  it('offers every federated strategy with its correct detail route and enables Microsoft through the shared endpoint', async () => {
    const strategies = ['google-oauth2', 'oauth2', 'oidc', 'windowslive', 'waad']
    const { wrapper, calls } = await mountAt(Detail, path, c => {
      const url = new URL(c.url).pathname
      if (url === '/api/v2/clients/m1') return { status: 200, body: client('m1') }
      if (url === '/api/v2/connections') return { status: 200, body: { connections: strategies.map(strategy => connection(strategy, { name: strategy, strategy, options: {} })), total: 5 } }
      if (url.endsWith('/clients')) return c.method === 'PATCH' ? { status: 204 } : { status: 200, body: { clients: [] } }
      return { status: 404 }
    })
    tabTo('Connections')
    await flushPromises()
    for (const strategy of strategies) {
      const row = wrapper.find(`[data-testid="conn-${strategy}"]`)
      const audience = ['oidc', 'waad'].includes(strategy) ? 'enterprise' : 'social'
      expect(row.find('a').attributes('href')).toBe(`/admin/t/acme/${audience}/${strategy}`)
      expect(row.find('input[role="switch"]').exists()).toBe(true)
    }
    await wrapper.find('[data-testid="conn-waad"] input').setValue(true)
    await flushPromises()
    expect(calls.find(c => c.method === 'PATCH')).toMatchObject({ url: 'https://acme.example.test/api/v2/connections/waad/clients', body: [{ client_id: 'm1', status: true }] })
    wrapper.unmount()
  })
})
