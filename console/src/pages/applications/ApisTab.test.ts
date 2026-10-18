import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { ClientGrant } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import { client, clientGrant, resourceServer, type Call } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/m1'
const body = () => document.body
const orders = resourceServer('r1', { name: 'Orders', identifier: 'https://orders.test', scopes: [{ value: 'read:orders' }, { value: 'write:orders' }] })
const billing = resourceServer('r2', { name: 'Billing', identifier: 'https://billing.test' })

function tabTo(name: string) {
  const trigger = Array.from(body().querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}
function button(label: string, root: ParentNode = body()): HTMLButtonElement {
  return Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
}

function backend(grants: ClientGrant[]) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/clients/m1') return { status: 200, body: client('m1', { name: 'Billing job', app_type: 'non_interactive' }) }
    if (u.pathname === '/api/v2/resource-servers') return { status: 200, body: { resource_servers: [orders, billing], start: 0, limit: 100, total: 2 } }
    if (u.pathname === '/api/v2/client-grants' && c.method === 'GET') {
      return { status: 200, body: { client_grants: grants, start: 0, limit: 100, total: grants.length } }
    }
    if (u.pathname === '/api/v2/client-grants' && c.method === 'POST') {
      const g = { ...(c.body as object), id: 'cgr_new' } as ClientGrant
      grants.push(g)
      return { status: 201, body: g }
    }
    const i = grants.findIndex((g) => u.pathname.endsWith('/' + g.id))
    if (c.method === 'DELETE') {
      grants.splice(i, 1)
      return { status: 204 }
    }
    grants[i] = { ...grants[i]!, ...(c.body as object) }
    return { status: 200, body: grants[i] }
  }
}

describe('Application APIs tab', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('lists the grants of this application and filters by its client ID', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, backend([clientGrant('cgr_1', 'm1', 'https://orders.test', { scope: ['read:orders'] })]))
    tabTo('APIs')
    await flushPromises()
    expect(calls.some((c) => c.url.includes('/client-grants?') && c.url.includes('client_id=m1'))).toBe(true)
    const row = body().querySelector('[data-testid="grant-https://orders.test"]')!
    expect(row.textContent).toContain('Orders')
    expect(row.querySelector<HTMLInputElement>('input[value="read:orders"]')!.checked).toBe(true)
    expect(row.querySelector<HTMLInputElement>('input[value="write:orders"]')!.checked).toBe(false)
    wrapper.unmount()
  })

  it('edits scopes and revokes', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, backend([clientGrant('cgr_1', 'm1', 'https://orders.test', { scope: ['read:orders'] })]))
    tabTo('APIs')
    await flushPromises()
    const row = () => body().querySelector('[data-testid="grant-https://orders.test"]')!
    row().querySelector<HTMLInputElement>('input[value="write:orders"]')!.click()
    await flushPromises()
    button('Save permissions', row()).click()
    await flushPromises()
    expect(calls.at(-1)!.method).toBe('PATCH')
    expect(calls.at(-1)!.body).toEqual({ scope: ['read:orders', 'write:orders'] })
    button('Revoke', row()).click()
    await flushPromises()
    expect(calls.at(-1)!.method).toBe('DELETE')
    expect(body().querySelector('[data-testid="grant-https://orders.test"]')).toBeNull()
    expect(body().textContent).toContain('not authorized to use any API yet')
    wrapper.unmount()
  })

  it('authorizes another API, offering only those not yet authorized', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, backend([clientGrant('cgr_1', 'm1', 'https://orders.test', { scope: [] })]))
    tabTo('APIs')
    await flushPromises()
    const select = body().querySelector<HTMLSelectElement>('#grant-api')!
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['', 'https://billing.test'])
    expect(button('Authorize').disabled).toBe(true)
    select.value = 'https://billing.test'
    select.dispatchEvent(new Event('change'))
    await flushPromises()
    button('Authorize').click()
    await flushPromises()
    expect(calls.at(-1)!.body).toEqual({ client_id: 'm1', audience: 'https://billing.test', subject_type: 'client', scope: [] })
    expect(body().querySelector('[data-testid="grant-https://billing.test"]')).not.toBeNull()
    expect(body().textContent).toContain('Every API in this tenant is already authorized.')
    wrapper.unmount()
  })

  it('shows an empty state, an action error, loading and a load error', async () => {
    const empty = await mountAt(Detail, path, backend([]))
    tabTo('APIs')
    await flushPromises()
    expect(body().textContent).toContain('not authorized to use any API yet')
    empty.wrapper.unmount()
    document.body.innerHTML = ''

    const refusing = await mountAt(Detail, path, (c) => (c.method === 'POST' ? apiError(409, 'client_grant_conflict', 'Already granted') : backend([])(c)))
    tabTo('APIs')
    await flushPromises()
    const select = body().querySelector<HTMLSelectElement>('#grant-api')!
    select.value = 'https://orders.test'
    select.dispatchEvent(new Event('change'))
    await flushPromises()
    button('Authorize').click()
    await flushPromises()
    expect(body().textContent).toContain('Already granted')
    refusing.wrapper.unmount()
    document.body.innerHTML = ''

    let fail = true
    const failing = await mountAt(Detail, path, (c) => (fail && new URL(c.url).pathname === '/api/v2/resource-servers' ? apiError(500, 'internal_error', 'Internal error') : backend([])(c)))
    tabTo('APIs')
    await flushPromises()
    expect(body().textContent).toContain('Internal error')
    fail = false
    button('Try again').click()
    await flushPromises()
    expect(body().querySelector('#grant-api')).not.toBeNull()
    failing.wrapper.unmount()
    document.body.innerHTML = ''

    const loading = await mountAt(Detail, path, (c) => (new URL(c.url).pathname === '/api/v2/resource-servers' ? new Promise(() => undefined) : backend([])(c)))
    tabTo('APIs')
    await flushPromises()
    expect(body().textContent).toContain('Loading…')
    loading.wrapper.unmount()
  })
})
