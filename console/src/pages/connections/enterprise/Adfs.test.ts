import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { servicesKey } from '../../../context'
import { mountAt } from '../../../test/mount'
import { fakeServices, connection, tenant } from '../../../test/services'
import AdfsSettings from './AdfsSettings.vue'
import Create from './Create.vue'

const item = connection('con_adfs', { name: 'corp-adfs', strategy: 'adfs', options: { adfs_server: 'adfs.example', signInEndpoint: 'https://adfs.example/adfs/ls/', thumbprints: ['ab'], thumbprints_sha384: ['cd'], prev_thumbprints: ['ef'] } })
async function settings() {
 const { services, calls, pinia, i18n } = fakeServices(() => ({ status: 200, body: item }))
 const wrapper = mount(AdfsSettings, { props: { tenant: tenant('acme'), connection: item }, attachTo: document.body, global: { plugins: [pinia, i18n], provide: { [servicesKey as symbol]: services } } })
 await flushPromises(); return { wrapper, calls }
}
async function create() {
 return mountAt(Create, '/t/acme/enterprise/new', c => new URL(c.url).pathname.endsWith('/clients') ? { status: 200, body: { clients: [], total: 0 } } : { status: 201, body: item })
}
describe('ADFS connections', () => {
 it('creates from an ADFS server without OAuth credentials', async () => {
  const { wrapper, calls } = await create()
  await wrapper.find('input[value="adfs"]').setValue(true)
  expect(wrapper.find('#social-client-id').exists()).toBe(false)
  expect(wrapper.find('#social-client-secret').exists()).toBe(false)
  await wrapper.find('#social-name').setValue('corp-adfs')
  const rp = wrapper.find('[data-testid="adfs-rp"]').text()
  expect(rp).toContain('urn:auth0:acme:corp-adfs')
  expect(rp).toContain('/login/callback')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
  await wrapper.find('#adfs-server').setValue('adfs.example')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'corp-adfs', strategy: 'adfs', options: { adfs_server: 'adfs.example' }, enabled_clients: [] })
  wrapper.unmount()
 })
 it('creates from a metadata document', async () => {
  const { wrapper, calls } = await create()
  await wrapper.find('input[value="adfs"]').setValue(true)
  await wrapper.find('#social-name').setValue('corp-adfs')
  await wrapper.find('#adfs-source').setValue('xml')
  await wrapper.find('#adfs-xml').setValue('<EntityDescriptor/>')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')?.body).toMatchObject({ strategy: 'adfs', options: { fedMetadataXml: '<EntityDescriptor/>' } })
  wrapper.unmount()
 })
 it('shows the relying party values and saves without read-only options', async () => {
  const { wrapper, calls } = await settings()
  expect(wrapper.get('[data-testid="adfs-rp"]').text()).toContain('urn:auth0:acme:corp-adfs')
  await wrapper.get('#adfs-user-id').setValue('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn')
  await wrapper.get('#adfs-email-verified').setValue(true)
  await wrapper.get('form').trigger('submit'); await flushPromises()
  const options = (calls.find(c => c.method === 'PATCH')?.body as { options: Record<string, unknown> }).options
  expect(options).toEqual({ adfs_server: 'adfs.example', user_id_attribute: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn', should_trust_email_verified_connection: 'always_set_emails_as_verified' })
  wrapper.unmount()
 })
})
