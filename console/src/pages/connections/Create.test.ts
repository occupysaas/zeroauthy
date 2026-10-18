import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { client, connection, type Call } from '../../test/services'
import Create from './Create.vue'

const apps = (c: Call) => {
  if (new URL(c.url).pathname === '/api/v2/clients') {
    const clients = [client('a1', { name: 'Web' }), client('a2', { name: 'Mobile' })]
    return { status: 200, body: { clients, start: 0, limit: 100, total: 2 } }
  }
  return undefined
}

describe('Create connection', () => {
  it('shows a fixed database type and lists the applications to enable', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/connections/new', (c) => apps(c) ?? { status: 200 })
    expect(wrapper.find<HTMLInputElement>('#conn-strategy').element.value).toBe('Database')
    expect(wrapper.findAll('input[type="checkbox"]')).toHaveLength(2)
    wrapper.unmount()
  })

  it('validates the name before calling the API', async () => {
    const { wrapper, calls } = await mountAt(Create, '/t/acme/connections/new', (c) => apps(c) ?? { status: 200 })
    const before = calls.length
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#conn-name-error').text()).toContain('Enter a name')
    for (const bad of ['-a', 'a-', 'a--b', 'a_b', 'a b']) {
      await wrapper.find('#conn-name').setValue(bad)
      await wrapper.find('form').trigger('submit')
      expect(wrapper.find('#conn-name-error').text(), bad).toContain('single hyphens')
    }
    await wrapper.find('#conn-name').setValue('a'.repeat(129))
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#conn-name-error').text()).toContain('at most 128')
    expect(calls).toHaveLength(before)
    wrapper.unmount()
  })

  it('creates the connection with the chosen applications and opens it', async () => {
    const { wrapper, router, calls } = await mountAt(Create, '/t/acme/connections/new', (c) => apps(c) ?? { status: 201, body: connection('con_new', { name: 'People-1' }) })
    await wrapper.find('#conn-name').setValue(' People-1 ')
    await wrapper.findAll('input[type="checkbox"]')[1]!.setValue(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('https://acme.example.test/api/v2/connections')
    expect(post.body).toEqual({ name: 'People-1', strategy: 'auth0', enabled_clients: ['a2'] })
    expect(router.currentRoute.value.path).toBe('/t/acme/connections/con_new')
    wrapper.unmount()
  })

  it('shows a used name on its field and other errors on top', async () => {
    let r = apiError(409, 'connection_conflict', 'The connection already exists')
    const { wrapper } = await mountAt(Create, '/t/acme/connections/new', (c) => apps(c) ?? r)
    await wrapper.find('#conn-name').setValue('dup')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('#conn-name-error').text()).toContain('already exists')
    r = apiError(500, 'internal_error', 'Internal error')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('#conn-name-error').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    wrapper.unmount()
  })

  it('says so when the applications cannot be listed or there are none', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/connections/new', () => apiError(500, 'internal_error', 'Boom'))
    expect(wrapper.text()).toContain('Boom')
    wrapper.unmount()
    const none = await mountAt(Create, '/t/acme/connections/new', () => ({ status: 200, body: { clients: [], start: 0, limit: 100, total: 0 } }))
    expect(none.wrapper.text()).toContain('no applications yet')
    none.wrapper.unmount()
  })
})
