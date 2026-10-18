import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { resourceServer } from '../../test/services'
import Create from './Create.vue'

describe('Create API', () => {
  it('shows the identifier hint and a fixed RS256', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/apis/new', () => ({ status: 200 }))
    expect(wrapper.find('#api-identifier-hint').text()).toContain('cannot be changed')
    const alg = wrapper.find<HTMLInputElement>('#api-alg')
    expect(alg.element.value).toBe('RS256')
    expect(alg.attributes('readonly')).toBeDefined()
    wrapper.unmount()
  })

  it('validates before calling the API', async () => {
    const { wrapper, calls } = await mountAt(Create, '/t/acme/apis/new', () => ({ status: 200 }))
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#api-name-error').text()).toContain('Enter a name')
    expect(wrapper.find('#api-identifier-error').text()).toContain('Enter an identifier')
    expect(calls).toHaveLength(0)
    wrapper.unmount()
  })

  it('creates the API and opens it', async () => {
    const { wrapper, router, calls } = await mountAt(Create, '/t/acme/apis/new', () => ({
      status: 201,
      body: resourceServer('abc123', { name: 'Orders' }),
    }))
    await wrapper.find('#api-name').setValue(' Orders ')
    await wrapper.find('#api-identifier').setValue('https://orders.example.test')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls[0]!.method).toBe('POST')
    expect(calls[0]!.url).toBe('https://acme.example.test/api/v2/resource-servers')
    expect(calls[0]!.body).toEqual({ name: 'Orders', identifier: 'https://orders.example.test', signing_alg: 'RS256' })
    expect(router.currentRoute.value.path).toBe('/t/acme/apis/abc123')
    wrapper.unmount()
  })

  it('shows a duplicate identifier on its field and other errors on top', async () => {
    let r = apiError(409, 'resource_server_conflict', 'An API with this identifier already exists')
    const { wrapper } = await mountAt(Create, '/t/acme/apis/new', () => r)
    await wrapper.find('#api-name').setValue('Orders')
    await wrapper.find('#api-identifier').setValue('dup')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('#api-identifier-error').text()).toContain('already exists')
    r = apiError(500, 'internal_error', 'Internal error')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('#api-identifier-error').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    wrapper.unmount()
  })
})
