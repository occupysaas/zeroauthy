import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { servicesKey } from '../../../context'
import { mountAt } from '../../../test/mount'
import { fakeServices, connection, tenant } from '../../../test/services'
import AdSettings from './AdSettings.vue'
import Create from './Create.vue'

const ticket = 'https://acme.example.test/p/ad/abcdefghijklmnopqrstuvwxyz012345'
const item = { ...connection('con_ad', { name: 'corp-ad', strategy: 'ad', options: { tenant_domain: 'corp.example', domain_aliases: ['corp.example'], ips: ['10.0.0.0/8'],
 kerberos: true, brute_force_protection: true, agentIP: '198.51.100.4', agentMode: true, agentVersion: '8.0.5', signInEndpoint: 'http://connector:4000/wsfed',
 certs: ['MIIB'], thumbprints: ['ab'.repeat(20)], thumbprints_sha384: ['cd'.repeat(48)] } }), provisioning_ticket_url: ticket }
async function settings(online: boolean) {
 const { services, calls, pinia, i18n } = fakeServices(c => new URL(c.url).pathname.endsWith('/status') ? (online ? { status: 200, body: '' } : { status: 404, body: { statusCode: 404, message: 'not connected to any node' } }) : { status: 200, body: item })
 const wrapper = mount(AdSettings, { props: { tenant: tenant('acme'), connection: item }, attachTo: document.body, global: { plugins: [pinia, i18n], provide: { [servicesKey as symbol]: services } } })
 await flushPromises(); return { wrapper, calls }
}
describe('AD/LDAP connections', () => {
 it('creates without OAuth credentials or callbacks', async () => {
  const { wrapper, calls } = await mountAt(Create, '/t/acme/enterprise/new', c => new URL(c.url).pathname.endsWith('/clients') ? { status: 200, body: { clients: [], total: 0 } } : { status: 201, body: item })
  await wrapper.find('input[value="ad"]').setValue(true)
  expect(wrapper.find('#social-client-id').exists()).toBe(false)
  expect(wrapper.find('#social-client-secret').exists()).toBe(false)
  await wrapper.find('#social-name').setValue('corp-ad')
  await wrapper.find('#ad-domain').setValue('Corp.Example')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'corp-ad', strategy: 'ad', options: { tenant_domain: 'corp.example' }, enabled_clients: [] })
  wrapper.unmount()
 })
 it('shows the ticket, connector and status, and saves without connector-managed options', async () => {
  const { wrapper, calls } = await settings(true)
  expect(wrapper.get('[data-testid="ad-ticket"]').text()).toBe(ticket)
  expect(wrapper.get('[data-testid="ad-status"]').text()).toContain('Online')
  expect(wrapper.get('[data-testid="ad-connector"]').text()).toContain('8.0.5')
  await wrapper.get('#ad-ips').setValue('10.0.0.0/8, 192.0.2.7')
  await wrapper.get('#ad-kerberos').setValue(false)
  await wrapper.get('form').trigger('submit'); await flushPromises()
  const options = (calls.find(c => c.method === 'PATCH')?.body as { options: Record<string, unknown> }).options
  expect(options).toEqual({ tenant_domain: 'corp.example', domain_aliases: ['corp.example'], ips: ['10.0.0.0/8', '192.0.2.7'], kerberos: false,
   disable_self_service_change_password: false, brute_force_protection: true, disable_cache: false })
  wrapper.unmount()
 })
 it('reports an offline connector', async () => {
  const { wrapper } = await settings(false)
  expect(wrapper.get('[data-testid="ad-status"]').text()).toContain('Not connected')
  wrapper.unmount()
 })
})
