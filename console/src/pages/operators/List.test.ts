import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { Operator } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import type { Call } from '../../test/services'
import List from './List.vue'

const body = () => document.body
const text = () => body().textContent ?? ''
const path = '/t/system/operators'

const ann: Operator = { user_id: 'auth0|a', email: 'ann@example.test', tenants: ['*'], created_at: '2026-10-01T10:00:00Z' }
const bob: Operator = { user_id: 'auth0|b', email: 'bob@example.test', tenants: ['acme', 'globex'], created_at: '2026-10-02T10:00:00Z' }

function button(label: string, root: ParentNode = body()): HTMLButtonElement {
  return Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
}
async function type(sel: string, v: string) {
  const el = body().querySelector<HTMLInputElement>(sel)!
  el.value = v
  el.dispatchEvent(new Event('input'))
  await flushPromises()
}

function backend(list: Operator[], onDelete?: (id: string) => ReturnType<typeof apiError> | { status: number }) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/system/operators' && c.method === 'GET') return { status: 200, body: list }
    if (u.pathname === '/api/system/operators' && c.method === 'POST') {
      const email = (c.body as { email: string }).email
      return { status: 201, body: { user_id: 'auth0|new', email, tenants: ['*'], created_at: '2026-10-18T00:00:00Z', setup_url: 'https://system.example.test/lo/reset?ticket=ONETIME' } }
    }
    if (c.method === 'DELETE') {
      const id = decodeURIComponent(u.pathname.split('/').pop()!)
      return onDelete ? onDelete(id) : { status: 204 }
    }
    return { status: 404 }
  }
}

describe('Operators', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('lists email, tenants and created', async () => {
    const { wrapper } = await mountAt(List, path, backend([ann, bob]))
    const rows = body().querySelectorAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]!.textContent).toContain('ann@example.test')
    expect(rows[0]!.textContent).toContain('All tenants')
    expect(rows[0]!.textContent).toContain('2026-10-01')
    expect(rows[1]!.textContent).toContain('acme, globex')
    wrapper.unmount()
  })

  it('is not served on a tenant that is not the system tenant', async () => {
    const { wrapper, calls } = await mountAt(List, '/t/acme/operators', backend([ann]))
    expect(calls).toHaveLength(0)
    expect(body().querySelector('table')).toBeNull()
    expect(text()).toContain('nothing at this address')
    wrapper.unmount()
  })

  it('shows an empty state and a load error with retry', async () => {
    const empty = await mountAt(List, path, backend([]))
    expect(text()).toContain('There are no operators.')
    empty.wrapper.unmount()
    document.body.innerHTML = ''
    let fail = true
    const failing = await mountAt(List, path, (c) => (fail ? apiError(500, 'internal_error', 'Internal error') : backend([ann])(c)))
    expect(text()).toContain('Internal error')
    fail = false
    button('Try again').click()
    await flushPromises()
    expect(text()).toContain('ann@example.test')
    failing.wrapper.unmount()
  })

  it('invites, shows the one-time link once with its expiry, and drops it on close', async () => {
    const { wrapper, calls } = await mountAt(List, path, backend([ann]))
    button('Invite operator').click()
    await flushPromises()
    button('Create invitation').click()
    await flushPromises()
    expect(text()).toContain('Enter an email address.')
    await type('#invite-email', 'not-an-address')
    button('Create invitation').click()
    await flushPromises()
    expect(text()).toContain('Enter a valid email address.')
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(0)

    await type('#invite-email', 'new@example.test')
    button('Create invitation').click()
    await flushPromises()
    expect(calls.at(-1)!.body).toEqual({ email: 'new@example.test' })
    const link = body().querySelector<HTMLInputElement>('#invite-url')!
    expect(link.value).toBe('https://system.example.test/lo/reset?ticket=ONETIME')
    expect(text()).toContain('expires in one hour')
    expect(button('Copy', body().querySelector('[data-testid="invite-link"]')!)).toBeDefined()
    // The new operator is in the list, without the link.
    expect(body().querySelector('[data-testid="operator-new@example.test"]')).not.toBeNull()

    button('Done').click()
    await flushPromises()
    expect(body().querySelector('#invite-url')).toBeNull()
    expect(text()).not.toContain('ONETIME')
    // Opening the dialog again starts from an empty form, not the old link.
    button('Invite operator').click()
    await flushPromises()
    expect(body().querySelector('#invite-url')).toBeNull()
    expect(body().querySelector<HTMLInputElement>('#invite-email')!.value).toBe('')
    wrapper.unmount()
  })

  it('shows an invite error', async () => {
    const { wrapper } = await mountAt(List, path, (c) => (c.method === 'POST' ? apiError(400, 'invalid_body', 'Invalid email') : backend([ann])(c)))
    button('Invite operator').click()
    await flushPromises()
    await type('#invite-email', 'x@example.test')
    button('Create invitation').click()
    await flushPromises()
    expect(text()).toContain('Invalid email')
    wrapper.unmount()
  })

  it('removes an operator after confirmation', async () => {
    const { wrapper, calls } = await mountAt(List, path, backend([ann, bob]))
    button('Remove').click()
    await flushPromises()
    expect(text()).toContain('Remove this operator?')
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    const dialog = body().querySelector('[role="dialog"]')!
    button('Remove', dialog).click()
    await flushPromises()
    const del = calls.find((c) => c.method === 'DELETE')!
    expect(del.url).toBe('https://admin.example.test/api/system/operators/auth0%7Ca')
    expect(body().querySelector('[data-testid="operator-ann@example.test"]')).toBeNull()
    expect(body().querySelector('[data-testid="status"]')!.textContent).toContain('ann@example.test was removed')
    wrapper.unmount()
  })

  it('cancelling leaves the operator', async () => {
    const { wrapper, calls } = await mountAt(List, path, backend([ann, bob]))
    button('Remove').click()
    await flushPromises()
    button('Cancel').click()
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    expect(body().querySelectorAll('tbody tr')).toHaveLength(2)
    wrapper.unmount()
  })

  it('says the last operator cannot be removed and keeps them', async () => {
    const { wrapper } = await mountAt(List, path, backend([ann], () => apiError(409, 'last_operator', 'The last operator cannot be removed')))
    button('Remove').click()
    await flushPromises()
    const dialog = () => body().querySelector('[role="dialog"]')!
    button('Remove', dialog()).click()
    await flushPromises()
    expect(body().querySelector('[data-testid="error-last_operator"]')!.textContent).toContain('last operator')
    expect(button('Remove', dialog()).disabled).toBe(true)
    expect(body().querySelector('[data-testid="operator-ann@example.test"]')).not.toBeNull()
    wrapper.unmount()
  })

  it('handles an operator that is already gone, and other errors', async () => {
    const gone = await mountAt(List, path, backend([ann, bob], () => apiError(404, 'inexistent_operator', 'x')))
    button('Remove').click()
    await flushPromises()
    button('Remove', body().querySelector('[role="dialog"]')!).click()
    await flushPromises()
    expect(text()).toContain('That operator no longer exists.')
    expect(body().querySelector('[data-testid="operator-ann@example.test"]')).toBeNull()
    gone.wrapper.unmount()
    document.body.innerHTML = ''

    const failing = await mountAt(List, path, backend([ann, bob], () => apiError(500, 'internal_error', 'Internal error')))
    button('Remove').click()
    await flushPromises()
    button('Remove', body().querySelector('[role="dialog"]')!).click()
    await flushPromises()
    expect(text()).toContain('Internal error')
    expect(body().querySelector('[data-testid="operator-ann@example.test"]')).not.toBeNull()
    failing.wrapper.unmount()
  })
})
