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
    expect(wrapper.findAll('input[name="strategy"]').map(i => (i.element as HTMLInputElement).value)).toEqual(['oidc', 'waad'])
    expect(wrapper.find('[data-testid="oidc-subset"]').text()).toContain('supported subset')
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
