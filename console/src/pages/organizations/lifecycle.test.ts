import { flushPromises, mount } from '@vue/test-utils'
import type { Component } from 'vue'
import { afterEach, expect, it } from 'vitest'
import { servicesKey } from '../../context'
import { apiError, mountAt } from '../../test/mount'
import { fakeServices, memoryRouter, tenant, type Reply } from '../../test/services'
import SettingsTab from './SettingsTab.vue'
import BrandingTab from './BrandingTab.vue'
import ConnectionsTab from './ConnectionsTab.vue'
import MembersTab from './MembersTab.vue'
import MemberRoles from './MemberRoles.vue'
import Detail from './Detail.vue'
import List from './List.vue'
import Create from './Create.vue'
const org = (name: string) => ({ id: 'org_' + name, name, display_name: name, third_party_client_access: 'block', is_app_entitlement_active: false, branding: { logo_url: 'https://' + name + '.test/logo' } })
afterEach(() => { document.body.innerHTML = '' })
async function panel(component: Component, handler: Parameters<typeof fakeServices>[0]) {
  const s = fakeServices(handler), router = memoryRouter(); await router.push('/t/acme/organizations/org_old')
  const wrapper = mount(component, { props: { tenant: tenant('acme'), organizationId: 'org_old', userId: 'auth0|u' }, global: { plugins: [s.pinia, s.i18n, router], provide: { [servicesKey as symbol]: s.services } } })
  await flushPromises(); return { wrapper, calls: s.calls }
}
const cases = [
  { component: SettingsTab, response: (name: string) => org(name), selector: '#organization-name', field: true },
  { component: BrandingTab, response: (name: string) => org(name), selector: '#organization-logo', field: true },
  { component: ConnectionsTab, response: (name: string) => ({ enabled_connections: [{ connection_id: name, connection: { name, strategy: 'auth0' } }], total: 1 }), selector: '', field: false },
  { component: MembersTab, response: (name: string) => ({ members: [{ user_id: name, email: name }], total: 1 }), selector: '', field: false },
  { component: MemberRoles, response: (name: string) => ({ roles: [{ id: name, name, description: '' }], total: 1 }), selector: '', field: false },
]
it.each(cases)('ignores stale reads in $component.__name after organization change', async ({ component, response, selector, field }) => {
  let resolve!: (r: Reply) => void
  const { wrapper } = await panel(component, c => c.url.includes('/api/v2/connections?') ? { status: 200, body: { connections: [], total: 0 } } : c.url.includes('org_old') ? new Promise(r => { resolve = r }) : { status: 200, body: response('fresh') })
  await wrapper.setProps({ organizationId: 'org_new' } as never); await flushPromises()
  resolve({ status: 200, body: response('obsolete') }); await flushPromises()
  if (field) expect((wrapper.get(selector).element as HTMLInputElement).value).toContain('fresh')
  else { expect(wrapper.text()).toContain('fresh'); expect(wrapper.text()).not.toContain('obsolete') }
  wrapper.unmount()
})
it('keeps the current detail when an older request finishes', async () => {
  let resolve!: (r: Reply) => void
  const { wrapper, router } = await mountAt(Detail, '/t/acme/organizations/org_old', c => c.url.endsWith('/org_old') ? new Promise(r => { resolve = r }) : { status: 200, body: org('fresh') })
  await router.push('/t/acme/organizations/org_new'); await flushPromises(); resolve({ status: 404, body: { message: 'obsolete' } }); await flushPromises()
  expect(wrapper.get('h1').text()).toBe('fresh'); expect(wrapper.text()).not.toContain('obsolete'); wrapper.unmount()
})
it('keeps list responses scoped to the selected tenant', async () => {
  let resolve!: (r: Reply) => void
  const { wrapper, router } = await mountAt(List, '/t/acme/organizations', c => c.url.includes('acme.example') ? new Promise(r => { resolve = r }) : { status: 200, body: { organizations: [org('fresh')], total: 1 } })
  await router.push('/t/system/organizations'); await flushPromises(); resolve({ status: 200, body: { organizations: [org('obsolete')], total: 1 } }); await flushPromises()
  expect(wrapper.text()).toContain('fresh'); expect(wrapper.text()).not.toContain('obsolete'); wrapper.unmount()
})
it('ignores a creation response after the tenant changes', async () => {
  let resolve!: (r: Reply) => void
  const { wrapper, router } = await mountAt(Create, '/t/acme/organizations/new', () => new Promise(r => { resolve = r }))
  await wrapper.get('#organization-name').setValue('draft'); await wrapper.get('form').trigger('submit'); await flushPromises()
  await router.push('/t/system/organizations/new'); await flushPromises(); resolve({ status: 201, body: org('obsolete') }); await flushPromises()
  expect(router.currentRoute.value.params.tenant).toBe('system'); expect(router.currentRoute.value.name).toBe('organization-new')
  expect((wrapper.get('#organization-name').element as HTMLInputElement).value).toBe(''); wrapper.unmount()
})
it('retains a failed settings draft and requires a reload before another write', async () => {
  const { wrapper, calls } = await panel(SettingsTab, c => c.method === 'PATCH' ? apiError(500, 'internal_error', 'Write uncertain') : { status: 200, body: org('fresh') })
  await wrapper.get('#organization-display-name').setValue('Unsaved'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect((wrapper.get('#organization-display-name').element as HTMLInputElement).value).toBe('Unsaved')
  expect(wrapper.text()).toContain('Reload before'); expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined()
  await wrapper.get('form').trigger('submit'); await flushPromises(); expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(1)
  await wrapper.findAll('button').find(b => b.text() === 'Reload')!.trigger('click'); await flushPromises()
  expect((wrapper.get('#organization-display-name').element as HTMLInputElement).value).toBe('fresh'); wrapper.unmount()
})
it.each([SettingsTab, BrandingTab])('ignores stale write errors and resets editor drafts', async component => {
  let resolve!: (r: Reply) => void
  const { wrapper } = await panel(component, c => c.method === 'PATCH' ? new Promise(r => { resolve = r }) : { status: 200, body: org(c.url.includes('org_old') ? 'original' : 'fresh') })
  const selector = component === SettingsTab ? '#organization-name' : '#organization-logo'
  await wrapper.get(selector).setValue(component === SettingsTab ? 'draft' : 'https://draft.test/logo'); await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.setProps({ organizationId: 'org_new' } as never); await flushPromises(); resolve(apiError(500, 'error', 'obsolete error')); await flushPromises()
  expect(wrapper.text()).not.toContain('obsolete error'); expect((wrapper.get(selector).element as HTMLInputElement).value).toContain('fresh'); wrapper.unmount()
})
