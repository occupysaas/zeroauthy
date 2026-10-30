import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { ClientGrant, ResourceServer } from '../../api/client'
import { apiError, mountAt, topDialog, dialogCount } from '../../test/mount'
import { client, clientGrant, resourceServer, type Call } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/apis/r1'
const body = () => document.body

function tabTo(name: string) {
  const trigger = Array.from(body().querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}

function button(label: string, root: ParentNode = body()): HTMLButtonElement {
  return Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
}

function setInput(el: HTMLInputElement, value: string) {
  el.value = value
  el.dispatchEvent(new Event('input'))
}

// A small in-memory tenant: one API, some machine applications, grants.
function backend(opts: { server?: ResourceServer; grants?: ClientGrant[] } = {}) {
  const state = {
    server: opts.server ?? resourceServer('r1', { name: 'Orders', scopes: [{ value: 'read:orders', description: 'Read' }, { value: 'write:orders' }] }),
    grants: opts.grants ?? [],
  }
  const handler = (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/resource-servers/r1') {
      if (c.method === 'PATCH') {
        state.server = { ...state.server, ...(c.body as object) }
        return { status: 200, body: state.server }
      }
      if (c.method === 'DELETE') return { status: 204 }
      return { status: 200, body: state.server }
    }
    if (u.pathname === '/api/v2/clients') {
      const clients = [client('m1', { name: 'Billing job', app_type: 'non_interactive' }), client('m2', { name: 'Report job', app_type: 'non_interactive' })]
      return { status: 200, body: { clients, start: 0, limit: 100, total: clients.length } }
    }
    if (u.pathname === '/api/v2/client-grants' && c.method === 'GET') {
      const audience = u.searchParams.get('audience')
      const list = state.grants.filter((g) => !audience || g.audience === audience)
      return { status: 200, body: { client_grants: list, start: 0, limit: 100, total: list.length } }
    }
    if (u.pathname === '/api/v2/client-grants' && c.method === 'POST') {
      const g = { ...(c.body as object), id: 'cgr_new' } as ClientGrant
      state.grants.push(g)
      return { status: 201, body: g }
    }
    if (u.pathname.startsWith('/api/v2/client-grants/')) {
      const i = state.grants.findIndex((g) => u.pathname.endsWith('/' + g.id))
      if (c.method === 'DELETE') {
        state.grants.splice(i, 1)
        return { status: 204 }
      }
      state.grants[i] = { ...state.grants[i]!, ...(c.body as object) }
      return { status: 200, body: state.grants[i] }
    }
    return { status: 404 }
  }
  return { state, handler }
}

describe('API detail', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('loads and shows the identifier with copy', async () => {
    const { handler } = backend()
    const { wrapper } = await mountAt(Detail, path, handler)
    expect(wrapper.find('[role="dialog"] h2').text()).toBe('Orders')
    expect(wrapper.find('[data-testid="identifier"]').text()).toBe('https://api.example.test/r1')
    expect(wrapper.find('#api-name').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-testid="system-badge"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('shows loading, a missing API and a failing load', async () => {
    const loading = await mountAt(Detail, path, () => new Promise(() => undefined))
    expect(loading.wrapper.find('[role="status"]').text()).toBe('Loading…')
    loading.wrapper.unmount()
    const missing = await mountAt(Detail, path, () => apiError(404, 'inexistent_resource_server', 'No such API'))
    expect(missing.wrapper.text()).toContain('There is nothing at this address.')
    missing.wrapper.unmount()
    const failing = await mountAt(Detail, path, () => apiError(500, 'internal_error', 'Internal error'))
    expect(failing.wrapper.text()).toContain('Internal error')
    failing.wrapper.unmount()
  })

  describe('settings', () => {
    it('validates lifetimes before saving', async () => {
      const { handler } = backend()
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      await wrapper.find('#api-lifetime').setValue('0')
      await wrapper.find('#api-lifetime-web').setValue('x')
      await wrapper.find('form:not(.danger-zone form)').trigger('submit')
      expect(wrapper.find('#api-lifetime-error').text()).toContain('from 1 to 2592000')
      expect(wrapper.find('#api-lifetime-web-error').exists()).toBe(true)
      await wrapper.find('#api-lifetime').setValue('3600')
      await wrapper.find('#api-lifetime-web').setValue('7200')
      await wrapper.find('form').trigger('submit')
      expect(wrapper.find('#api-lifetime-web-error').text()).toContain('cannot exceed')
      expect(calls.some((c) => c.method === 'PATCH')).toBe(false)
      wrapper.unmount()
    })

    it('saves every setting', async () => {
      const { handler } = backend()
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      await wrapper.find('#api-name').setValue('Orders v2')
      await wrapper.find('#api-lifetime').setValue('3600')
      await wrapper.find('#api-lifetime-web').setValue('1800')
      await wrapper.findAll('input[type="checkbox"]')[0]!.setValue(true)
      await wrapper.findAll('input[type="checkbox"]')[1]!.setValue(true)
      await wrapper.find('#api-user-policy').setValue('deny_all')
      await wrapper.find('#api-client-policy').setValue('deny_all')
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('PATCH')
      expect(calls.at(-1)!.body).toEqual({
        name: 'Orders v2',
        token_lifetime: 3600,
        token_lifetime_for_web: 1800,
        allow_offline_access: true,
        enforce_policies: false,
        token_dialect: 'access_token',
        skip_consent_for_verifiable_first_party_clients: true,
        subject_type_authorization: { user: { policy: 'deny_all' }, client: { policy: 'deny_all' } },
      })
      expect(wrapper.text()).toContain('Saved')
      expect(wrapper.find('[role="dialog"] h2').text()).toBe('Orders v2')
      wrapper.unmount()
    })

    it('shows the API’s field errors', async () => {
      const { handler } = backend()
      const { wrapper } = await mountAt(Detail, path, (c) =>
        c.method === 'PATCH' ? apiError(400, 'invalid_body', 'Payload validation error: token_lifetime_for_web must not exceed token_lifetime; something else') : handler(c),
      )
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(wrapper.find('#api-lifetime-web-error').text()).toContain('must not exceed')
      expect(wrapper.find('[role="alert"]').text()).toBe('something else')
      wrapper.unmount()
    })
  })

  describe('a system API', () => {
    const system = resourceServer('r1', {
      name: 'zeroauthy Management API',
      is_system: true,
      scopes: [{ value: 'read:clients' }],
      subject_type_authorization: { user: { policy: 'deny_all' }, client: { policy: 'require_client_grant' } },
    })

    it('is marked, read-only except the lifetimes, and has no danger zone', async () => {
      const { handler } = backend({ server: system })
      const { wrapper } = await mountAt(Detail, path, handler)
      expect(wrapper.find('[data-testid="system-badge"]').text()).toBe('System')
      for (const sel of ['#api-name', '#api-user-policy', '#api-client-policy', 'input[type="checkbox"]']) {
        expect(wrapper.find(sel).attributes('disabled')).toBeDefined()
      }
      expect(wrapper.find('#api-lifetime').attributes('disabled')).toBeUndefined()
      const tabs = Array.from(body().querySelectorAll('[role="tab"]')).map((x) => x.textContent?.trim())
      expect(tabs).not.toContain('Danger zone')
      tabTo('Permissions')
      await flushPromises()
      expect(body().textContent).toContain('read:clients')
      expect(body().querySelector('#scope-value')).toBeNull()
      expect(button('Remove')).toBeUndefined()
      wrapper.unmount()
    })

    it('sends only the lifetimes and shows the server’s refusal', async () => {
      const { handler } = backend({ server: system })
      let refuse = true
      const { wrapper, calls } = await mountAt(Detail, path, (c) =>
        c.method === 'PATCH' && refuse ? apiError(400, 'invalid_body', 'Payload validation error: token_lifetime cannot be lowered here') : handler(c),
      )
      await wrapper.find('#api-lifetime').setValue('1200')
      await wrapper.find('#api-lifetime-web').setValue('600')
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(calls.at(-1)!.body).toEqual({ token_lifetime: 1200, token_lifetime_for_web: 600 })
      expect(wrapper.find('#api-lifetime-error').text()).toContain('cannot be lowered here')
      refuse = false
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(wrapper.text()).toContain('Saved')
      wrapper.unmount()
    })
  })

  describe('permissions', () => {
    it('shows an empty list and adds a permission', async () => {
      const { handler } = backend({ server: resourceServer('r1', { name: 'Orders' }) })
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      tabTo('Permissions')
      await flushPromises()
      expect(body().querySelector('[data-testid="scopes-empty"]')).not.toBeNull()
      setInput(body().querySelector('#scope-value')!, 'read:orders')
      setInput(body().querySelector('#scope-description')!, 'Read orders')
      body().querySelector('#scope-value')!.closest('form')!.dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().textContent).toContain('read:orders')
      expect(body().textContent).toContain('You have unsaved changes')
      button('Save permissions').click()
      await flushPromises()
      expect(calls.at(-1)!.body).toEqual({ scopes: [{ value: 'read:orders', description: 'Read orders' }] })
      expect(body().textContent).toContain('Saved')
      wrapper.unmount()
    })

    it('validates a new permission', async () => {
      const { handler } = backend()
      const { wrapper } = await mountAt(Detail, path, handler)
      tabTo('Permissions')
      await flushPromises()
      const form = body().querySelector('#scope-value')!.closest('form')!
      form.dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().querySelector('#scope-value-error')!.textContent).toContain('Enter a permission')
      setInput(body().querySelector('#scope-value')!, 'read:orders')
      form.dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().querySelector('#scope-value-error')!.textContent).toContain('already defined')
      wrapper.unmount()
    })

    it('removes an unused permission without a warning', async () => {
      const { handler } = backend()
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      tabTo('Permissions')
      await flushPromises()
      button('Remove').click()
      await flushPromises()
      button('Save permissions').click()
      await flushPromises()
      expect(dialogCount()).toBe(1)
      expect(calls.at(-1)!.body).toEqual({ scopes: [{ value: 'write:orders' }] })
      wrapper.unmount()
    })

    it('warns before removing a permission that grants carry', async () => {
      const { handler, state } = backend({ grants: [clientGrant('cgr_1', 'm1', 'https://api.example.test/r1', { scope: ['read:orders'] })] })
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      tabTo('Permissions')
      await flushPromises()
      button('Remove').click() // read:orders is first
      await flushPromises()
      button('Save permissions').click()
      await flushPromises()
      const dialog = topDialog()!
      expect(dialog.textContent).toContain('read:orders is granted to 1 application')
      expect(calls.some((c) => c.method === 'PATCH')).toBe(false)
      button('Cancel', dialog).click()
      await flushPromises()
      expect(calls.some((c) => c.method === 'PATCH')).toBe(false)
      button('Save permissions').click()
      await flushPromises()
      button('Remove and save', topDialog()!).click()
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('PATCH')
      expect(state.server.scopes).toEqual([{ value: 'write:orders' }])
      expect(dialogCount()).toBe(1)
      wrapper.unmount()
    })

    it('shows the API’s refusal', async () => {
      const { handler } = backend()
      const { wrapper } = await mountAt(Detail, path, (c) => (c.method === 'PATCH' ? apiError(400, 'invalid_body', 'Payload validation error: scopes are fixed') : handler(c)))
      tabTo('Permissions')
      await flushPromises()
      button('Remove').click()
      await flushPromises()
      button('Save permissions').click()
      await flushPromises()
      expect(body().textContent).toContain('scopes are fixed')
      wrapper.unmount()
    })
  })

  describe('machine-to-machine applications', () => {
    it('lists every machine application with its switch', async () => {
      const { handler } = backend({ grants: [clientGrant('cgr_1', 'm1', 'https://api.example.test/r1', { scope: ['read:orders'] })] })
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      tabTo('Machine-to-machine applications')
      await flushPromises()
      expect(calls.some((c) => c.url.includes('/clients?') && c.url.includes('app_type=non_interactive'))).toBe(true)
      expect(calls.some((c) => c.url.includes('/client-grants?') && c.url.includes('audience=https%3A%2F%2Fapi.example.test%2Fr1'))).toBe(true)
      const sw = (id: string) => body().querySelector<HTMLInputElement>(`[data-testid="m2m-${id}"] input[role="switch"]`)!
      expect(sw('m1').checked).toBe(true)
      expect(sw('m2').checked).toBe(false)
      expect(body().querySelector('[data-testid="m2m-m2"] fieldset')).toBeNull()
      expect(body().querySelector<HTMLInputElement>('[data-testid="m2m-m1"] input[value="read:orders"]')!.checked).toBe(true)
      wrapper.unmount()
    })

    it('grants, picks scopes, saves per application and revokes', async () => {
      const { handler, state } = backend()
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      tabTo('Machine-to-machine applications')
      await flushPromises()
      const sw = () => body().querySelector<HTMLInputElement>('[data-testid="m2m-m2"] input[role="switch"]')!
      sw().click()
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('POST')
      expect(calls.at(-1)!.body).toEqual({ client_id: 'm2', audience: 'https://api.example.test/r1', subject_type: 'client', scope: [] })
      const row = () => body().querySelector('[data-testid="m2m-m2"]')!
      expect(sw().checked).toBe(true)
      row().querySelector<HTMLInputElement>('input[value="write:orders"]')!.click()
      await flushPromises()
      button('Save permissions', row()).click()
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('PATCH')
      expect(calls.at(-1)!.url).toContain('/api/v2/client-grants/cgr_new')
      expect(calls.at(-1)!.body).toEqual({ scope: ['write:orders'] })
      expect(row().textContent).toContain('Saved')
      expect(state.grants[0]!.scope).toEqual(['write:orders'])
      // All permissions
      row().querySelector<HTMLInputElement>('[data-testid="grant-cgr_new-all"]')!.click()
      await flushPromises()
      expect(row().querySelector<HTMLInputElement>('input[value="read:orders"]')!.disabled).toBe(true)
      button('Save permissions', row()).click()
      await flushPromises()
      expect(calls.at(-1)!.body).toEqual({ allow_all_scopes: true })
      // Revoke
      sw().click()
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('DELETE')
      expect(sw().checked).toBe(false)
      expect(row().querySelector('fieldset')).toBeNull()
      wrapper.unmount()
    })

    it('shows the API’s refusal on the row and leaves the switch off', async () => {
      const { handler } = backend()
      const { wrapper } = await mountAt(Detail, path, (c) => (c.method === 'POST' ? apiError(409, 'client_grant_conflict', 'The grant already exists') : handler(c)))
      tabTo('Machine-to-machine applications')
      await flushPromises()
      const sw = body().querySelector<HTMLInputElement>('[data-testid="m2m-m1"] input[role="switch"]')!
      sw.click()
      await flushPromises()
      expect(body().querySelector('[data-testid="m2m-m1"]')!.textContent).toContain('The grant already exists')
      expect(wrapper.exists()).toBe(true)
      wrapper.unmount()
    })

    it('shows an empty state, loading and an error with retry', async () => {
      const { handler } = backend()
      const empty = await mountAt(Detail, path, (c) =>
        new URL(c.url).pathname === '/api/v2/clients' ? { status: 200, body: { clients: [], start: 0, limit: 100, total: 0 } } : handler(c),
      )
      tabTo('Machine-to-machine applications')
      await flushPromises()
      expect(body().textContent).toContain('no machine-to-machine applications yet')
      empty.wrapper.unmount()

      let fail = true
      const failing = await mountAt(Detail, path, (c) => (fail && new URL(c.url).pathname === '/api/v2/clients' ? apiError(500, 'internal_error', 'Internal error') : handler(c)))
      tabTo('Machine-to-machine applications')
      await flushPromises()
      expect(body().textContent).toContain('Internal error')
      fail = false
      button('Try again').click()
      await flushPromises()
      expect(body().querySelectorAll('input[role="switch"]')).toHaveLength(2)
      failing.wrapper.unmount()

      const loading = await mountAt(Detail, path, (c) => (new URL(c.url).pathname === '/api/v2/clients' ? new Promise(() => undefined) : handler(c)))
      tabTo('Machine-to-machine applications')
      await flushPromises()
      expect(body().textContent).toContain('Loading…')
      loading.wrapper.unmount()
    })
  })

  describe('danger zone', () => {
    it('deletes only once the name is typed and warns about grants and consents', async () => {
      const { handler } = backend()
      const { wrapper, router, calls } = await mountAt(Detail, path, handler)
      tabTo('Danger zone')
      await flushPromises()
      button('Delete API').click()
      await flushPromises()
      const dialog = topDialog()!
      expect(dialog.textContent).toContain('grant for this API')
      expect(dialog.textContent).toContain('consents')
      const confirm = () => button('Delete API', dialog)
      expect(confirm().disabled).toBe(true)
      setInput(dialog.querySelector('#delete-confirm')!, 'Order')
      await flushPromises()
      expect(confirm().disabled).toBe(true)
      setInput(dialog.querySelector('#delete-confirm')!, 'Orders')
      await flushPromises()
      confirm().click()
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('DELETE')
      expect(router.currentRoute.value.name).toBe('apis')
      wrapper.unmount()
    })

    it('asks for the identifier when the API has no name', async () => {
      const { handler } = backend({ server: resourceServer('r1', { name: undefined }) })
      const { wrapper, calls } = await mountAt(Detail, path, handler)
      expect(wrapper.find('[role="dialog"] h2').text()).toBe('(no name)')
      tabTo('Danger zone')
      await flushPromises()
      button('Delete API').click()
      await flushPromises()
      const dialog = topDialog()!
      setInput(dialog.querySelector('#delete-confirm')!, 'https://api.example.test/r1')
      await flushPromises()
      button('Delete API', dialog).click()
      await flushPromises()
      expect(calls.at(-1)!.method).toBe('DELETE')
      wrapper.unmount()
    })

    it('shows a failed delete', async () => {
      const { handler } = backend()
      const { wrapper } = await mountAt(Detail, path, (c) => (c.method === 'DELETE' ? apiError(500, 'internal_error', 'Internal error') : handler(c)))
      tabTo('Danger zone')
      await flushPromises()
      button('Delete API').click()
      await flushPromises()
      const dialog = topDialog()!
      setInput(dialog.querySelector('#delete-confirm')!, 'Orders')
      await flushPromises()
      button('Delete API', dialog).click()
      await flushPromises()
      expect(dialog.textContent).toContain('Internal error')
      wrapper.unmount()
    })
  })
})
