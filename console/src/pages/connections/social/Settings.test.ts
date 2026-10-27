import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { connection } from '../../../test/services'
import Detail from './Detail.vue'

const clientId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
describe('Microsoft settings', () => {
  it.each(['windowslive', 'waad'])('keeps %s identity bindings read-only and omits unchanged secret', async strategy => {
    const options = { client_id: clientId, ...(strategy === 'waad' ? { tenant_domain: 'acme.onmicrosoft.com', useCommonEndpoint: false, domain: 'Display only' } : { strategy_version: 2 }) }
    const item = connection('con_ms', { strategy, options })
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/enterprise/con_ms', () => ({ status: 200, body: item }), { domains: ['login.acme.com', 'other.acme.com'] })
    expect(wrapper.find<HTMLInputElement>('#social-client-id').element.readOnly).toBe(true)
    expect(wrapper.find('#social-script').exists()).toBe(false)
    expect(wrapper.find('#social-scope').exists()).toBe(false)
    if (strategy === 'waad') {
      expect(wrapper.find<HTMLInputElement>('#microsoft-tenant').element.readOnly).toBe(true)
      expect(wrapper.find<HTMLInputElement>('#microsoft-mode').element.readOnly).toBe(true)
    }
    expect(wrapper.findAll('[data-testid="callbacks"] code').map(c => c.text())).toEqual(['https://acme.example.test/login/callback', 'https://login.acme.com/login/callback', 'https://other.acme.com/login/callback'])
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect((calls.find(c => c.method === 'PATCH')?.body as { options: unknown }).options).toEqual(options)
    await wrapper.find('#social-secret').setValue('   ')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#social-secret-error').exists()).toBe(true)
    expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(1)
    await wrapper.find('#social-secret').setValue('rotated')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect((calls.filter(c => c.method === 'PATCH')[1]?.body as { options: Record<string, unknown> }).options.client_secret).toBe('rotated')
    expect(wrapper.find<HTMLInputElement>('#social-secret').element.value).toBe('')
    wrapper.unmount()
  })

  it('shows the any-organization warning in immutable multitenant settings', async () => {
    const item = connection('con_ms', { strategy: 'waad', options: { client_id: clientId, useCommonEndpoint: true } })
    const { wrapper } = await mountAt(Detail, '/t/acme/enterprise/con_ms', () => ({ status: 200, body: item }))
    expect(wrapper.find('#microsoft-tenant').exists()).toBe(false)
    expect(wrapper.find('[data-testid="any-organization-warning"]').text()).toContain('every organizational directory')
    wrapper.unmount()
  })
})
