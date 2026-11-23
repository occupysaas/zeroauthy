import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { connection } from '../../../test/services'
import Create from './Create.vue'

async function open() {
  return mountAt(Create, '/t/acme/enterprise/new', c => new URL(c.url).pathname.endsWith('/clients') ? { status: 200, body: { clients: [], total: 0 } } : { status: 201, body: connection('con_work', { strategy: 'waad' }) })
}
async function credentials(wrapper: Awaited<ReturnType<typeof open>>['wrapper']) {
  await wrapper.find('input[value="waad"]').setValue(true)
  await wrapper.find('#social-name').setValue('work')
  await wrapper.find('#social-client-id').setValue('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
  await wrapper.find('#social-client-secret').setValue('secret')
}

describe('Enterprise setup', () => {
  it('offers generic OIDC and Microsoft work/school without duplicating Google', async () => {
    const { wrapper } = await open()
    expect(wrapper.findAll('input[name="strategy"]').map(i => (i.element as HTMLInputElement).value)).toEqual(['oidc', 'okta', 'waad', 'samlp', 'adfs', 'google-apps'])
    expect(wrapper.find('[data-testid="oidc-subset"]').text()).toContain('Enterprise OIDC')
    expect(wrapper.find('#social-discovery').exists()).toBe(true)
    wrapper.unmount()
  })

  it.each(['ACME.OnMicrosoft.com', 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'])('normalizes single-directory tenant %s in its exact payload', async tenant => {
    const { wrapper, calls, router } = await open()
    await credentials(wrapper)
    await wrapper.find('#microsoft-tenant').setValue(tenant)
    expect(wrapper.find('#social-script').exists()).toBe(false)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'work', strategy: 'waad', enabled_clients: [], options: { client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', client_secret: 'secret', identity_api: 'microsoft-identity-platform-v2.0', waad_protocol: 'openid-connect', userid_attribute: 'oid', useCommonEndpoint: false, tenant_domain: tenant.toLowerCase() } })
    expect(router.currentRoute.value.name).toBe('enterprise-connection')
    wrapper.unmount()
  })

  it('warns that any organization is eligible and omits the hidden tenant even after mode changes', async () => {
    const { wrapper, calls } = await open()
    await credentials(wrapper)
    await wrapper.find('#microsoft-tenant').setValue('acme.onmicrosoft.com')
    await wrapper.find('#microsoft-mode').setValue('organizations')
    expect(wrapper.find('#microsoft-tenant').exists()).toBe(false)
    expect(wrapper.find('[data-testid="any-organization-warning"]').text()).toContain('every organizational directory')
    expect(wrapper.text()).toContain('multitenant')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const options = (calls.find(c => c.method === 'POST')?.body as { options: Record<string, unknown> }).options
    expect(options.useCommonEndpoint).toBe(true)
    expect(options).not.toHaveProperty('tenant_domain')
    expect(options).not.toHaveProperty('scope')
    wrapper.unmount()
  })

  it.each(['common', 'organizations', 'consumers', '9188040d-6c67-4c5b-b112-36a304b66dad', 'https://acme.com', 'acme.com:443', ' acme.com', 'acme..com', 'école.com', 'a'.repeat(254)])('rejects invalid or reserved tenant %s', async tenant => {
    const { wrapper, calls } = await open()
    await credentials(wrapper)
    await wrapper.find('#microsoft-tenant').setValue(tenant)
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#microsoft-tenant-error').exists()).toBe(true)
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
    wrapper.unmount()
  })
})

it('creates front-channel OIDC without storing an unused secret', async () => {
 const {wrapper,calls}=await open()
 await wrapper.find('#social-name').setValue('front')
 await wrapper.find('#social-client-id').setValue('client')
 await wrapper.find('#social-discovery').setValue('https://idp.example/discovery')
 await wrapper.find('#oidc-channel').setValue('front_channel')
 expect(wrapper.find('#social-client-secret').exists()).toBe(false)
 await wrapper.find('form').trigger('submit');await flushPromises()
 const body=calls.find(c=>c.method==='POST')?.body as {options:Record<string,unknown>}
 expect(body.options.type).toBe('front_channel');expect(body.options).not.toHaveProperty('client_secret')
 wrapper.unmount()
})
it('creates an Okta connection from its domain',async()=>{
 const {wrapper,calls}=await open()
 await wrapper.find('input[value="okta"]').setValue(true)
 await wrapper.find('#social-name').setValue('workforce')
 await wrapper.find('#social-client-id').setValue('client')
 await wrapper.find('#social-client-secret').setValue('fixture')
 await wrapper.find('#okta-domain').setValue('DEV-1.OKTA.COM')
 await wrapper.find('form').trigger('submit');await flushPromises()
 const body=calls.find(c=>c.method==='POST')?.body as {strategy:string;options:Record<string,unknown>}
 expect(body.strategy).toBe('okta');expect(body.options.domain).toBe('dev-1.okta.com');expect(body.options.type).toBe('back_channel')
 expect(body.options).not.toHaveProperty('discovery_url');wrapper.unmount()
})

describe('Google Workspace setup', () => {
  it('sends the Workspace domain and shows the directory consent callback', async () => {
    const { wrapper, calls } = await open()
    await wrapper.find('input[value="google-apps"]').setValue(true)
    await wrapper.find('#social-name').setValue('workspace')
    await wrapper.find('#social-client-id').setValue('ws-client')
    await wrapper.find('#social-client-secret').setValue('secret')
    expect(wrapper.find('[data-testid="callbacks"]').text()).toContain('/directory-provisioning/callback')
    await wrapper.find('#workspace-domain').setValue('localhost')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find(c => c.method === 'POST')).toBeUndefined()
    await wrapper.find('#workspace-domain').setValue('Corp.Example.com')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'workspace', strategy: 'google-apps', enabled_clients: [], options: { client_id: 'ws-client', client_secret: 'secret', domain: 'corp.example.com', tenant_domain: 'corp.example.com' } })
    wrapper.unmount()
  })
})
