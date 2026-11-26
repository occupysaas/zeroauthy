import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { Client, ClientGrant, ResourceServer } from '../../api/client'
import { mountAt } from '../../test/mount'
import { client, resourceServer, type Call } from '../../test/services'
import List from './List.vue'
import AppDetail from '../applications/Detail.vue'
import RoleDetail from '../roles/Detail.vue'

const ORG = 'https://acme.example.test/my-org/'
const myOrg = () => resourceServer('mo', { name: 'My Organization API', identifier: ORG, is_system: true, enforce_policies: true, token_lifetime: 600, scopes: [{ value: 'read:my_org:members' }, { value: 'read:my_org:details' }], subject_type_authorization: { user: { policy: 'require_client_grant' }, client: { policy: 'deny_all' } } })

afterEach(() => {
  document.body.innerHTML = ''
})

describe('My Organization API (Plan 42b)', () => {
  it('offers activation and creates the system API', async () => {
    const servers: ResourceServer[] = [resourceServer('r1')]
    const { wrapper, calls } = await mountAt(List, '/t/acme/apis', (c: Call) => {
      if (c.method === 'POST') {
        servers.push(myOrg())
        return { status: 201, body: servers[servers.length - 1] }
      }
      return { status: 200, body: { resource_servers: servers, start: 0, limit: 100, total: servers.length } }
    })
    const card = wrapper.find('[data-testid="my-org-card"]')
    expect(card.text()).toContain('My Organization API')
    await card.find('button').trigger('click')
    await flushPromises()
    expect(calls.find((c) => c.method === 'POST')!.body).toMatchObject({ identifier: ORG })
    expect(wrapper.find('[data-testid="my-org-card"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('grants user access and saves the application configuration', async () => {
    const grants: ClientGrant[] = []
    let app: Client = client('m1', { name: 'Portal', app_type: 'spa' })
    const { wrapper, calls } = await mountAt(AppDetail, '/t/acme/applications/m1', (c: Call) => {
      const u = new URL(c.url)
      if (u.pathname === '/api/v2/clients/m1' && c.method === 'PATCH') {
        app = { ...app, ...(c.body as object) } as Client
        return { status: 200, body: app }
      }
      if (u.pathname === '/api/v2/clients/m1') return { status: 200, body: app }
      if (u.pathname === '/api/v2/clients') return { status: 200, body: { clients: [app], start: 0, limit: 100, total: 1 } }
      if (u.pathname === '/api/v2/resource-servers') return { status: 200, body: { resource_servers: [myOrg()], start: 0, limit: 100, total: 1 } }
      if (u.pathname === '/api/v2/connection-profiles') return { status: 200, body: { connection_profiles: [{ id: 'cop_1', name: 'SSO with SCIM' }] } }
      if (u.pathname === '/api/v2/client-grants' && c.method === 'GET') return { status: 200, body: { client_grants: grants, start: 0, limit: 100, total: grants.length } }
      if (u.pathname === '/api/v2/client-grants' && c.method === 'POST') {
        const g = { ...(c.body as object), id: 'cgr_o' } as ClientGrant
        grants.push(g)
        return { status: 201, body: g }
      }
      return { status: 200, body: {} }
    })
    const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === 'APIs')!
    trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    trigger.focus()
    await flushPromises()
    const section = document.body.querySelector('[data-testid="my-org-access"]')!
    expect(section.textContent).toContain('My Organization API')
    Array.from(section.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Allow user access')!.click()
    await flushPromises()
    expect(calls.find((c) => c.method === 'POST' && c.url.endsWith('/client-grants'))!.body).toMatchObject({ audience: ORG, subject_type: 'user' })
    const form = document.body.querySelector<HTMLFormElement>('[data-testid="my-org-config"]')!
    const landing = form.querySelector<HTMLSelectElement>('#my-org-landing')!
    landing.value = 'm1'
    landing.dispatchEvent(new Event('change'))
    const profile = form.querySelector<HTMLSelectElement>('#my-org-profile')!
    expect(profile.textContent).toContain('SSO with SCIM')
    profile.value = 'cop_1'
    profile.dispatchEvent(new Event('change'))
    const ceiling = form.querySelector<HTMLInputElement>('#my-org-ceiling')!
    ceiling.checked = true
    ceiling.dispatchEvent(new Event('change'))
    form.dispatchEvent(new Event('submit'))
    await flushPromises()
    const patch = calls.find((c) => c.method === 'PATCH' && c.url.endsWith('/clients/m1'))!
    expect(patch.body).toEqual({ my_organization_configuration: { allowed_strategies: [], connection_deletion_behavior: 'allow', invitation_landing_client_id: 'm1', connection_profile_id: 'cop_1', enforce_permission_ceiling: true, enforce_self_assignment_restriction: false } })
    wrapper.unmount()
  })

  it('marks a role visible to the API', async () => {
    const { wrapper, calls } = await mountAt(RoleDetail, '/t/acme/roles/rol_1', (c: Call) => {
      if (c.url.includes('/users')) return { status: 200, body: { users: [], total: 0, start: 0, limit: 1 } }
      const visible = c.method === 'PATCH' ? (c.body as { my_organization_visible: boolean }).my_organization_visible : false
      return { status: 200, body: { id: 'rol_1', name: 'Org Admin', description: '', my_organization_visible: visible } }
    })
    await wrapper.get('#role-my-org').setValue(true)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'PATCH')!.body).toEqual({ name: 'Org Admin', description: '', my_organization_visible: true })
    wrapper.unmount()
  })
})
