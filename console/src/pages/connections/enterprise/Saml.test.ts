import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { servicesKey } from '../../../context'
import { mountAt } from '../../../test/mount'
import { fakeServices, connection, tenant } from '../../../test/services'
import SamlSettings from './SamlSettings.vue'
import Create from './Create.vue'

const pem = '-----BEGIN CERTIFICATE-----\nMIIBthrowaway\n-----END CERTIFICATE-----'
const item = connection('con_saml', { name: 'corp-saml', strategy: 'samlp', options: { signInEndpoint: 'https://idp.example/sso', signingCert: pem, thumbprints: ['ab'], thumbprints_sha384: ['cd'], fieldsMap: { email: 'mail' } } })
async function settings() {
 const { services, calls, pinia, i18n } = fakeServices(() => ({ status: 200, body: item }))
 const wrapper = mount(SamlSettings, { props: { tenant: tenant('acme'), connection: item }, attachTo: document.body, global: { plugins: [pinia, i18n], provide: { [servicesKey as symbol]: services } } })
 await flushPromises(); return { wrapper, calls }
}
async function create() {
 return mountAt(Create, '/t/acme/enterprise/new', c => new URL(c.url).pathname.endsWith('/clients') ? { status: 200, body: { clients: [], total: 0 } } : { status: 201, body: item })
}
describe('SAML connections', () => {
 it('creates from a metadata URL without OAuth credentials', async () => {
  const { wrapper, calls } = await create()
  await wrapper.find('input[value="samlp"]').setValue(true)
  expect(wrapper.find('#social-client-id').exists()).toBe(false)
  expect(wrapper.find('#social-client-secret').exists()).toBe(false)
  await wrapper.find('#social-name').setValue('corp-saml')
  expect(wrapper.find('[data-testid="saml-acs"]').text()).toContain('/login/callback?connection=corp-saml')
  await wrapper.find('#saml-metadata-url').setValue('https://idp.example/metadata')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'corp-saml', strategy: 'samlp', options: { metadataUrl: 'https://idp.example/metadata' }, enabled_clients: [] })
  wrapper.unmount()
 })
 it('creates manually and refuses a missing certificate', async () => {
  const { wrapper, calls } = await create()
  await wrapper.find('input[value="samlp"]').setValue(true)
  await wrapper.find('#social-name').setValue('corp-saml')
  await wrapper.find('#saml-source').setValue('manual')
  await wrapper.find('#saml-signin').setValue('https://idp.example/sso')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
  await wrapper.find('#saml-cert').setValue(pem)
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')?.body).toMatchObject({ strategy: 'samlp', options: { signInEndpoint: 'https://idp.example/sso', signingCert: pem } })
  wrapper.unmount()
 })
 it('shows SP values and saves without read-only thumbprints', async () => {
  const { wrapper, calls } = await settings()
  const sp = wrapper.get('[data-testid="saml-sp"]').text()
  expect(sp).toContain('urn:auth0:acme:corp-saml')
  expect(sp).toContain('/samlp/metadata?connection=corp-saml')
  await wrapper.get('#saml-idp').setValue(true)
  await wrapper.get('#saml-idp-client').setValue('app')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  const options = (calls.find(c => c.method === 'PATCH')?.body as { options: Record<string, unknown> }).options
  expect(options).toMatchObject({ signInEndpoint: 'https://idp.example/sso', signingCert: pem, fieldsMap: { email: 'mail' }, idpinitiated: { enabled: true, client_id: 'app' } })
  expect(options).not.toHaveProperty('thumbprints'); expect(options).not.toHaveProperty('thumbprints_sha384')
  wrapper.unmount()
 })
 it('refuses a non-HTTPS sign-in URL and a non-object attribute map', async () => {
  const { wrapper, calls } = await settings()
  await wrapper.get('#saml-signin').setValue('http://idp.example/sso')
  await wrapper.get('#saml-fields').setValue('[]')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0)
  expect(wrapper.text()).toContain('Enter a JSON object.')
  wrapper.unmount()
 })
})
