import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { servicesKey } from '../../context'
import { fakeServices, tenant, connection, type Reply } from '../../test/services'
import ConnectionsTab from './ConnectionsTab.vue'
import MembersTab from './MembersTab.vue'
import MemberRoles from './MemberRoles.vue'
import OrganizationsTab from '../users/OrganizationsTab.vue'
import { memoryRouter } from '../../test/services'
const orgID = 'org_1234567890123456'
afterEach(() => { document.body.innerHTML = '' })
async function setup(component: object, props: object, handler: Parameters<typeof fakeServices>[0]) {
  const s = fakeServices(handler), router = memoryRouter(); await router.push('/t/acme/organizations/' + orgID)
  const wrapper = mount(component, { props: { tenant: tenant('acme'), organizationId: orgID, ...props }, global: { plugins: [s.pinia, s.i18n, router], provide: { [servicesKey as symbol]: s.services } } }); await flushPromises()
  return { wrapper, calls: s.calls }
}
it('enables connections with strategy-specific flags and updates signup atomically', async () => {
  const entries = ['auth0', 'oidc', 'google-oauth2'].map(strategy => ({ connection_id: strategy, connection: { name: strategy, strategy }, assign_membership_on_login: false, is_signup_enabled: false, show_as_button: true }))
  const { wrapper, calls } = await setup(ConnectionsTab, {}, c => ({ status: 200, body: c.url.includes('/organizations/') ? { connections: entries, total: 3 } : { connections: [connection('con_new')], total: 1 } }))
  expect(wrapper.get('[data-connection="auth0"] [data-flag="show_as_button"]').attributes('disabled')).toBeDefined()
  expect(wrapper.get('[data-connection="oidc"] [data-flag="is_signup_enabled"]').attributes('disabled')).toBeDefined()
  expect(wrapper.get('[data-connection="auth0"] [data-flag="is_signup_enabled"]').attributes('disabled')).toBeDefined()
  await wrapper.get('[data-connection="auth0"] [data-flag="assign_membership_on_login"]').setValue(true); await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ assign_membership_on_login: true }); wrapper.unmount()
})
it('searches users then adds and removes membership', async () => {
  let added = false
  const { wrapper, calls } = await setup(MembersTab, {}, c => {
    if (c.method !== 'GET') { added = true; return { status: 204 } }
    if (c.url.includes('/users?')) return { status: 200, body: { users: [{ user_id: 'auth0|a', email: 'a@test' }], total: 1 } }
    return { status: 200, body: { members: added ? [{ user_id: 'auth0|a', email: 'a@test' }] : [], total: added ? 1 : 0 } }
  })
  await wrapper.get('#organization-user-search').setValue('email:"a@test"'); await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.findAll('button').find(b => b.text() === 'Add member')!.trigger('click'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')!.body).toEqual({ members: ['auth0|a'] })
  await wrapper.findAll('button').find(b => b.text() === 'Remove member')!.trigger('click'); await flushPromises()
  expect(calls.find(c => c.method === 'DELETE')!.body).toEqual({ members: ['auth0|a'] }); wrapper.unmount()
})
it('assigns a member role using the scoped path and displays role limit', async () => {
  const { wrapper, calls } = await setup(MemberRoles, { userId: 'auth0|a' }, c => c.method !== 'GET' ? { status: 204 } : { status: 200, body: { roles: [{ id: 'rol_a', name: 'Editor', description: '' }], total: 1 } })
  await wrapper.get('#organization-role-id').setValue('rol_a'); await wrapper.get('form').trigger('submit'); await flushPromises()
  const call = calls.find(c => c.method === 'POST')!
  expect(call.url).toContain('/members/auth0%7Ca/roles'); expect(call.body).toEqual({ roles: ['rol_a'] }); expect(wrapper.text()).toContain('50'); wrapper.unmount()
})
it('shows user organizations and ignores an old user reply', async () => {
  let resolve!: (r: Reply) => void
  const { wrapper } = await setup(OrganizationsTab, { userId: 'old' }, c => c.url.includes('/old/') ? new Promise(r => { resolve = r }) : { status: 200, body: { organizations: [{ id: orgID, name: 'new', display_name: 'New' }], total: 1 } })
  await wrapper.setProps({ userId: 'new' } as never); await flushPromises(); resolve({ status: 200, body: { organizations: [{ id: orgID, name: 'old', display_name: 'Old' }], total: 1 } }); await flushPromises()
  expect(wrapper.text()).toContain('New'); expect(wrapper.text()).not.toContain('Old'); wrapper.unmount()
})
it('enables and disables a connection and clears the successful enable selection', async () => {
  let enabled = false
  const { wrapper, calls } = await setup(ConnectionsTab, {}, c => {
    if (c.method === 'POST') { enabled = true; return { status: 201, body: {} } }
    if (c.method === 'DELETE') { enabled = false; return { status: 204 } }
    return { status: 200, body: c.url.includes('/organizations/') ? { connections: enabled ? [{ connection_id: 'db', connection: { name: 'Database', strategy: 'auth0' } }] : [], total: enabled ? 1 : 0 } : { connections: [connection('db')], total: 1 } }
  })
  await wrapper.get('#organization-connection').setValue('db'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')!.body).toEqual({ connection_id: 'db' })
  expect((wrapper.get('#organization-connection').element as HTMLSelectElement).value).toBe('')
  expect(wrapper.findAll('button').find(b => b.text() === 'Enable connection')!.attributes('disabled')).toBeDefined()
  await wrapper.findAll('button').find(b => b.text() === 'Remove connection')!.trigger('click'); await flushPromises()
  expect(calls.find(c => c.method === 'DELETE')!.url).toContain('/connections/db'); expect(wrapper.text()).toContain('No associated connections'); wrapper.unmount()
})
it('disables signup atomically when auto-membership is turned off', async () => {
  const { wrapper, calls } = await setup(ConnectionsTab, {}, c => ({ status: 200, body: c.url.includes('/organizations/') ? { connections: [{ connection_id: 'db', connection: { name: 'Database', strategy: 'auth0' }, assign_membership_on_login: true, is_signup_enabled: true, show_as_button: true }], total: 1 } : { connections: [], total: 0 } }))
  await wrapper.get('[data-flag="assign_membership_on_login"]').setValue(false); await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ assign_membership_on_login: false, is_signup_enabled: false }); wrapper.unmount()
})
it('disabled connection remains manageable', async () => {
 const { wrapper, calls } = await setup(ConnectionsTab, {}, c => ({ status: 200, body: c.url.includes('/organizations/') ? { connections: [{ connection_id: 'db', is_enabled: false, organization_connection_name: 'Local database', organization_access_level: 'readonly', organization_member_access_level: 'limited', connection: { name: 'Database', strategy: 'auth0' } }], total: 1 } : { connections: [], total: 0 } }))
 expect(wrapper.text()).toContain('Local database'); expect(wrapper.get('[data-flag="is_enabled"]').attributes('disabled')).toBeUndefined(); await wrapper.get('[data-flag="is_enabled"]').setValue(true); await flushPromises(); expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ is_enabled: true }); expect(calls.find(c => c.method === 'PATCH')!.url).toContain('/connections/db'); expect(wrapper.text()).toContain('Stored only'); wrapper.unmount()
})
it('removes member roles using the organization and member path', async () => {
 const { wrapper, calls } = await setup(MemberRoles, { userId: 'auth0|a' }, c => c.method === 'DELETE' ? { status: 204 } : { status: 200, body: { roles: [{ id: 'rol_a', name: 'Editor' }], total: 1 } }); await wrapper.findAll('button').find(b => b.text() === 'Remove role')!.trigger('click'); await flushPromises(); expect(calls.find(c => c.method === 'DELETE')!.url).toContain('/members/auth0%7Ca/roles'); expect(calls.find(c => c.method === 'DELETE')!.body).toEqual({ roles: ['rol_a'] }); wrapper.unmount()
})
it('legacy connection capability never exposes discarded settings', async () => {
 const { wrapper } = await setup(ConnectionsTab, {}, c => c.url.includes('/organizations/') && !c.url.includes('enabled_connections') ? { status: 501, body: { errorCode: 'organizations_ii_unavailable', message: 'Unsupported' } } : { status: 200, body: c.url.includes('enabled_connections') ? { enabled_connections: [{ connection_id: 'db', connection: { name: 'Database', strategy: 'auth0' } }], total: 1 } : { connections: [], total: 0 } }); expect(wrapper.text()).toContain('Database'); expect(wrapper.find('[data-flag="is_enabled"]').exists()).toBe(false); expect(wrapper.text()).toContain('Connection names and delegation settings are unavailable'); wrapper.unmount()
})
