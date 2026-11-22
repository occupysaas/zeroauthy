import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../../test/mount'
import { client, connection, type Call } from '../../../test/services'
import Create from './Create.vue'
import { appleKey } from '../../../test/apple'
import { githubScopeFlags } from './social'
import { appStorageKeys } from '../../../test/storage'

const apps = (c: Call) =>
  new URL(c.url).pathname === '/api/v2/clients' ? { status: 200, body: { clients: [client('a1', { name: 'Web' })], start: 0, limit: 100, total: 1 } } : undefined

async function open(handler: (c: Call) => unknown = () => ({ status: 201, body: connection('con_new', { strategy: 'oidc' }) }), extra = {}) {
  return mountAt(Create, '/t/acme/social/new', (c) => apps(c) ?? (handler(c) as never), extra)
}

describe('Create social connection', () => {
  it('offers social providers once and keeps generic OIDC reachable through Enterprise', async () => {
    const { wrapper } = await open()
    expect(wrapper.findAll('input[name="strategy"]').map((i) => (i.element as HTMLInputElement).value)).toEqual(['google-oauth2', 'oauth2', 'windowslive', 'apple', 'github'])
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
    expect(appStorageKeys()).toEqual([])
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

describe('Apple setup', () => {
  it('checks the pasted key and sends Apple fields without a client_secret', async () => {
    const { wrapper, calls } = await open()
    await wrapper.find('input[value="apple"]').setValue(true)
    await wrapper.find('#social-name').setValue('apple')
    await wrapper.find('#social-client-id').setValue('test.acme.web')
    await wrapper.find('#apple-team').setValue('ABCDE12345')
    await wrapper.find('#apple-kid').setValue('ABCDE67890')
    await wrapper.find('#apple-key').setValue('invalid-private-material')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(wrapper.find('#apple-key-error').text()).toContain('PKCS#8')
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
    await wrapper.find('#apple-key').setValue(appleKey)
    await wrapper.find('#apple-name').setValue(false)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'apple', strategy: 'apple', enabled_clients: [], options: { client_id: 'test.acme.web', team_id: 'ABCDE12345', kid: 'ABCDE67890', app_secret: appleKey, name: false, email: true } })
    expect(wrapper.find<HTMLTextAreaElement>('#apple-key').element.value).toBe('')
    wrapper.unmount()
  })
})

describe('GitHub setup', () => {
  async function fill(wrapper: Awaited<ReturnType<typeof open>>['wrapper']) {
    await wrapper.find('input[value="github"]').setValue(true)
    await wrapper.find('#social-name').setValue('github')
    await wrapper.find('#social-client-id').setValue('Iv1.testclientid0000')
    await wrapper.find('#social-client-secret').setValue('fixture-secret')
  }

  it('sends the flags and email, never scope, and shows the derived scope', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper)
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.value).toBe('user:email')
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.readOnly).toBe(true)
    await wrapper.find('#github-scope-repo').setValue(true)
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.value).toBe('user:email repo')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.find(c => c.method === 'POST')?.body).toEqual({ name: 'github', strategy: 'github', enabled_clients: [], options: { client_id: 'Iv1.testclientid0000', client_secret: 'fixture-secret', email: true, repo: true } })
    expect(wrapper.find<HTMLInputElement>('#social-client-secret').element.value).toBe('')
    wrapper.unmount()
  })

  it('requires the secret and allows an empty scope', async () => {
    const { wrapper, calls } = await open()
    await wrapper.find('input[value="github"]').setValue(true)
    await wrapper.find('#social-name').setValue('github')
    await wrapper.find('#social-client-id').setValue('Iv1.testclientid0000')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(wrapper.find('#social-client-secret-error').exists()).toBe(true)
    await wrapper.find('#social-client-secret').setValue('fixture-secret')
    await wrapper.find('#github-email').setValue(false)
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.value).toBe('')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect((calls.find(c => c.method === 'POST')?.body as { options: unknown }).options).toEqual({ client_id: 'Iv1.testclientid0000', client_secret: 'fixture-secret', email: false })
    wrapper.unmount()
  })

  it('lists the eighteen flags in order, as native keyboard-operable checkboxes', async () => {
    const { wrapper } = await open()
    await wrapper.find('input[value="github"]').setValue(true)
    const boxes = wrapper.findAll<HTMLInputElement>('#github-email, [id^="github-scope-"]')
    expect(boxes).toHaveLength(19)
    expect(boxes.slice(1).map(b => b.element.id.replace('github-scope-', ''))).toEqual(githubScopeFlags.map(f => f.option))
    // Native checkboxes in a label toggle with Space and stay in the tab order.
    for (const b of boxes) {
      expect(b.element.type).toBe('checkbox')
      expect(b.attributes('tabindex')).toBeUndefined()
      expect(b.element.disabled).toBe(false)
      expect(b.element.closest('label')?.textContent?.trim()).not.toBe('')
    }
    wrapper.unmount()
  })

  it('keeps the form within a narrow viewport', async () => {
    const { wrapper } = await open(undefined, { domains: ['login.acme.com'] })
    await wrapper.find('input[value="github"]').setValue(true)
    // jsdom has no layout: assert the wrapping classes and the absence of fixed widths.
    const form = wrapper.find('[data-testid="github-options"]')
    expect(form.find('fieldset').classes()).toContain('min-w-0')
    expect(form.findAll('fieldset label.check span').every(s => s.classes().includes('break-all'))).toBe(true)
    expect(wrapper.find('[data-testid="callbacks"]').classes()).toContain('break-all')
    expect(wrapper.find('form').html()).not.toMatch(/\bw-(?:[1-9]|\[)|min-w-(?:[1-9]|\[)/)
    wrapper.unmount()
  })

  it('shows the OAuth app note and the register-every-URL note with one URL per origin', async () => {
    const { wrapper } = await open(undefined, { domains: ['login.acme.com'] })
    await wrapper.find('input[value="github"]').setValue(true)
    expect(wrapper.find('[data-testid="github-options"]').text()).toContain('GitHub App gets its permissions from its own registration')
    expect(wrapper.find('[data-testid="github-callbacks"]').text()).toContain('Register every listed URL exactly')
    expect(wrapper.findAll('[data-testid="callbacks"] code').map(c => c.text())).toEqual(['https://acme.example.test/login/callback', 'https://login.acme.com/login/callback'])
    wrapper.unmount()
  })
})
