import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../../test/mount'
import { client, connection, type Call } from '../../../test/services'
import Create from './Create.vue'

const apps = (c: Call) =>
  new URL(c.url).pathname === '/api/v2/clients' ? { status: 200, body: { clients: [client('a1', { name: 'Web' })], start: 0, limit: 100, total: 1 } } : undefined

async function open(handler: (c: Call) => unknown = () => ({ status: 201, body: connection('con_new', { strategy: 'oidc' }) }), extra = {}) {
  return mountAt(Create, '/t/acme/social/new', (c) => apps(c) ?? (handler(c) as never), extra)
}

describe('Create social connection', () => {
  it('offers social providers once and keeps generic OIDC reachable through Enterprise', async () => {
    const { wrapper } = await open()
    expect(wrapper.findAll('input[name="strategy"]').map((i) => (i.element as HTMLInputElement).value)).toEqual(['google-oauth2', 'oauth2', 'windowslive'])
    expect(wrapper.find('[data-testid="oidc-subset"]').exists()).toBe(false)
    expect(wrapper.find('a[href="/admin/t/acme/enterprise/new"]').exists()).toBe(true)
    await wrapper.find('input[value="oauth2"]').setValue(true)
    expect(wrapper.find('#social-script').exists()).toBe(true)
    wrapper.unmount()
  })

  it('requires credentials and https endpoints before calling the API', async () => {
    const { wrapper, calls } = await open()
    await wrapper.find('input[value="oauth2"]').setValue(true)
    await wrapper.find('#social-name').setValue('prov')
    await wrapper.find('#social-authorize').setValue('http://provider.example/a')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#social-client-id-error').text()).toContain('required')
    expect(wrapper.find('#social-client-secret-error').text()).toContain('required')
    expect(wrapper.find('#social-authorize-error').text()).toContain('https')
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(0)
    wrapper.unmount()
  })

  it('refuses an oversized script', async () => {
    const { wrapper, calls } = await open()
    await wrapper.find('input[value="oauth2"]').setValue(true)
    await wrapper.find('#social-script').setValue('x'.repeat(65537))
    expect(wrapper.find('[data-testid="social-script-size"]').text()).toContain('larger than 65536')
    await wrapper.find('form').trigger('submit')
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(0)
    wrapper.unmount()
  })

  it('shows callback URLs for the canonical host and custom domains', async () => {
    const { wrapper } = await open(undefined, { domains: ['login.acme.com'] })
    expect(wrapper.findAll('[data-testid="callbacks"] code').map((c) => c.text())).toEqual([
      'https://acme.example.test/login/callback',
      'https://login.acme.com/login/callback',
    ])
    wrapper.unmount()
  })

  it('creates an OIDC connection once and opens it', async () => {
    const { wrapper, calls, router } = await mountAt(Create, '/t/acme/enterprise/new', (c) => apps(c) ?? { status: 201, body: connection('con_new', { strategy: 'oidc' }) })
    await wrapper.find('input[value="oidc"]').setValue(true)
    await wrapper.find('#social-name').setValue('corp')
    await wrapper.find('#social-client-id').setValue('cid')
    await wrapper.find('#social-client-secret').setValue('s3cret')
    await wrapper.find('#social-discovery').setValue('https://idp.example/.well-known/openid-configuration')
    await wrapper.find('input[type="checkbox"][value="a1"]').setValue(true)
    const form = wrapper.find('form')
    await form.trigger('submit')
    await form.trigger('submit') // a double submission sends one request
    await flushPromises()
    const posts = calls.filter((c) => c.method === 'POST')
    expect(posts).toHaveLength(1)
    expect(posts[0]!.body).toEqual({
      name: 'corp', strategy: 'oidc', enabled_clients: ['a1'],
      options: { client_id: 'cid', client_secret: 's3cret', type: 'back_channel', discovery_url: 'https://idp.example/.well-known/openid-configuration', scopes: 'openid profile email' },
    })
    expect(router.currentRoute.value.path).toBe('/t/acme/enterprise/con_new')
    expect(window.localStorage.length + window.sessionStorage.length).toBe(0)
    wrapper.unmount()
  })

  it('reports an uncertain write without claiming success, keeping the draft', async () => {
    const { wrapper, router } = await open(() => {
      throw new TypeError('network down')
    })
    await wrapper.find('#social-name').setValue('goog')
    await wrapper.find('#social-client-id').setValue('cid')
    await wrapper.find('#social-client-secret').setValue('s')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('may have been created')
    expect((wrapper.find('#social-name').element as HTMLInputElement).value).toBe('goog')
    expect(router.currentRoute.value.path).toBe('/t/acme/social/new')
    wrapper.unmount()
  })

  it('shows API validation errors', async () => {
    const { wrapper } = await open(() => apiError(400, 'invalid_body', 'Payload validation error: options.scopes must contain openid'))
    await wrapper.find('#social-name').setValue('goog')
    await wrapper.find('#social-client-id').setValue('cid')
    await wrapper.find('#social-client-secret').setValue('s')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('must contain openid')
    wrapper.unmount()
  })
})


describe('Microsoft personal setup', () => {
  it('uses v2 and fixed scopes with no script and lists every callback', async () => {
    const { wrapper, calls } = await open(undefined, { domains: ['login.acme.com', 'other.acme.com'] })
    await wrapper.find('input[value="windowslive"]').setValue(true)
    expect(wrapper.text()).toContain('Microsoft identity platform v2')
    expect(wrapper.text()).toContain('openid profile email')
    expect(wrapper.text()).toContain('email may be missing')
    expect(wrapper.find('#social-script').exists()).toBe(false)
    expect(wrapper.find('#social-scopes').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="callbacks"] code')).toHaveLength(3)
    await wrapper.find('#social-name').setValue('personal')
    await wrapper.find('#social-client-id').setValue('AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE')
    await wrapper.find('#social-client-secret').setValue('secret')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'personal', strategy: 'windowslive', enabled_clients: [], options: { client_id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', client_secret: 'secret', strategy_version: 2 } })
    wrapper.unmount()
  })

  it('rejects non-GUID client IDs and blank Microsoft secrets', async () => {
    const { wrapper, calls } = await open()
    await wrapper.find('input[value="windowslive"]').setValue(true)
    await wrapper.find('#social-name').setValue('personal')
    await wrapper.find('#social-client-id').setValue('not-a-guid')
    await wrapper.find('#social-client-secret').setValue('   ')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#social-client-id-error').text()).toContain('GUID')
    expect(wrapper.find('#social-client-secret-error').exists()).toBe(true)
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
    wrapper.unmount()
  })
})
