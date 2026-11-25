import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { ClientGrant, ResourceServer } from '../../api/client'
import { mountAt } from '../../test/mount'
import { client, clientGrant, resourceServer, type Call } from '../../test/services'
import List from './List.vue'
import AppDetail from '../applications/Detail.vue'

const ME = 'https://acme.example.test/me/'
const myAccount = () => resourceServer('ma', { name: 'Auth0 My Account API', identifier: ME, is_system: true, scopes: [{ value: 'read:me:authentication_methods' }, { value: 'read:me:factors' }], subject_type_authorization: { user: { policy: 'require_client_grant' }, client: { policy: 'deny_all' } } })

function listBackend(servers: ResourceServer[]) {
  return (c: Call) => {
    if (c.method === 'POST') {
      servers.push(myAccount())
      return { status: 201, body: servers[servers.length - 1] }
    }
    return { status: 200, body: { resource_servers: servers, start: 0, limit: 100, total: servers.length } }
  }
}

describe('My Account API activation (Plan 42a)', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('offers activation and creates the system API with its identifier', async () => {
    const servers = [resourceServer('r1')]
    const { wrapper, calls } = await mountAt(List, '/t/acme/apis', listBackend(servers))
    const card = wrapper.find('[data-testid="my-account-card"]')
    expect(card.text()).toContain('My Account API')
    await card.find('button').trigger('click')
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('https://acme.example.test/api/v2/resource-servers')
    expect(post.body).toMatchObject({ identifier: ME })
    expect(wrapper.find('[data-testid="my-account-card"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('Auth0 My Account API')
    wrapper.unmount()
  })

  it('shows no activation card once active', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/apis', listBackend([myAccount()]))
    expect(wrapper.find('[data-testid="my-account-card"]').exists()).toBe(false)
    wrapper.unmount()
  })
})

function button(label: string): HTMLButtonElement {
  return Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
}

describe('Application My Account access (Plan 42a)', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('creates and revokes the user grant; the API is not offered to machine grants', async () => {
    const grants: ClientGrant[] = []
    const backend = (c: Call) => {
      const u = new URL(c.url)
      if (u.pathname === '/api/v2/clients/m1') return { status: 200, body: client('m1', { name: 'Web app', app_type: 'spa' }) }
      if (u.pathname === '/api/v2/resource-servers') return { status: 200, body: { resource_servers: [myAccount()], start: 0, limit: 100, total: 1 } }
      if (u.pathname === '/api/v2/client-grants' && c.method === 'GET') return { status: 200, body: { client_grants: grants, start: 0, limit: 100, total: grants.length } }
      if (u.pathname === '/api/v2/client-grants' && c.method === 'POST') {
        const g = { ...(c.body as object), id: 'cgr_u' } as ClientGrant
        grants.push(g)
        return { status: 201, body: g }
      }
      if (c.method === 'DELETE') {
        grants.splice(0, 1)
        return { status: 204 }
      }
      return { status: 200, body: grants[0] }
    }
    const { wrapper, calls } = await mountAt(AppDetail, '/t/acme/applications/m1', backend)
    const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === 'APIs')!
    trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    trigger.focus()
    await flushPromises()
    expect(document.body.querySelector('#grant-api option[value="' + ME + '"]')).toBeNull()
    const section = document.body.querySelector('[data-testid="my-account-access"]')!
    expect(section.textContent).toContain('My Account API')
    button('Allow user access').click()
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.body).toMatchObject({ client_id: 'm1', audience: ME, subject_type: 'user', scope: ['read:me:authentication_methods', 'read:me:factors'] })
    expect(document.body.querySelector('[data-testid="my-account-access"] input[value="read:me:factors"]')).not.toBeNull()
    button('Remove user access').click()
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE' && c.url.endsWith('/client-grants/cgr_u'))).toBe(true)
    expect(document.body.querySelector('[data-testid="my-account-access"]')!.textContent).toContain('Allow user access')
    wrapper.unmount()
    expect(clientGrant).toBeDefined()
  })
})

describe('My Account API detail (Plan 42a)', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('can be deactivated, unlike other system APIs', async () => {
    const { default: Detail } = await import('./Detail.vue')
    const tabs = async (s: ResourceServer) => {
      const { wrapper } = await mountAt(Detail, '/t/acme/apis/' + s.id, () => ({ status: 200, body: s }))
      const names = Array.from(document.body.querySelectorAll('[role="tab"]')).map((x) => x.textContent?.trim())
      wrapper.unmount()
      document.body.innerHTML = ''
      return names
    }
    expect(await tabs(myAccount())).toContain('Danger zone')
    expect(await tabs(resourceServer('sys', { is_system: true, identifier: 'https://acme.example.test/api/v2/' }))).not.toContain('Danger zone')
  })
})
