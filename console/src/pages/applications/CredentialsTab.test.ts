import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { ClientCredential } from '../../api/client'
import { apiError, mountAt, topDialog } from '../../test/mount'
import { client } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/abc'

function tabTo(name: string) {
  const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find((t) => t.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}

const cred = (id: string, extra: Partial<ClientCredential> = {}): ClientCredential => ({
  id, name: 'Key ' + id, kid: 'kid-' + id + '-0123456789', alg: 'RS256', credential_type: 'public_key',
  thumbprint_sha256: 'x', created_at: '2026-11-01T00:00:00Z', updated_at: '2026-11-01T00:00:00Z', ...extra,
})

// credentialsServer answers the credentials routes from a mutable list.
function server(list: ClientCredential[]) {
  return (c: { method: string; url: string }) => {
    if (c.url.endsWith('/credentials')) {
      if (c.method === 'POST') { const n = cred('cred_new'); list.push(n); return { status: 201, body: n } }
      return { status: 200, body: list }
    }
    if (c.method === 'DELETE') { list.splice(0, 1); return { status: 204 } }
    return { status: 200, body: client('abc') }
  }
}

afterEach(() => { document.body.innerHTML = '' })

describe('Credentials tab', () => {
  it('adds a public key with the PEM in the request body', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, server([]))
    tabTo('Credentials')
    await flushPromises()
    expect(wrapper.find('[data-testid="cred-empty"]').exists()).toBe(true)
    await wrapper.find('#cred-name').setValue('Laptop')
    await wrapper.find('#cred-pem').setValue('-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----')
    await wrapper.find('#cred-expires').setValue('2027-01-02')
    await wrapper.find('#cred-alg').setValue('PS256')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('https://acme.example.test/api/v2/clients/abc/credentials')
    expect(post.body).toEqual({ credential_type: 'public_key', name: 'Laptop', alg: 'PS256', expires_at: '2027-01-02T00:00:00.000Z', pem: '-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----' })
    expect(wrapper.findAll('[data-testid="credential"]')).toHaveLength(1)
    wrapper.unmount()
  })

  it('requires a PEM before calling the API', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, server([]))
    tabTo('Credentials')
    await flushPromises()
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#cred-pem-error').text()).toContain('Paste a PEM')
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    wrapper.unmount()
  })

  it('disables the add button at two keys', async () => {
    const { wrapper } = await mountAt(Detail, path, server([cred('one'), cred('two')]))
    tabTo('Credentials')
    await flushPromises()
    expect(wrapper.find('[data-testid="cred-full"]').exists()).toBe(true)
    const add = wrapper.findAll('button').find((b) => b.text() === 'Add key')!
    expect(add.attributes('disabled')).toBeDefined()
    wrapper.unmount()
  })

  it('removes a key after confirmation and refreshes the application', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, server([cred('one')]))
    tabTo('Credentials')
    await flushPromises()
    await wrapper.findAll('button').find((b) => b.text() === 'Remove')!.trigger('click')
    await flushPromises()
    const confirm = Array.from(topDialog()!.querySelectorAll<HTMLButtonElement>('button')).find((b) => b.textContent?.trim() === 'Remove')!
    confirm.click()
    await flushPromises()
    expect(calls.find((c) => c.method === 'DELETE')!.url).toBe('https://acme.example.test/api/v2/clients/abc/credentials/one')
    expect(wrapper.find('[data-testid="cred-empty"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('explains a storage plugin without the capability', async () => {
    const { wrapper } = await mountAt(Detail, path, (c) => c.url.endsWith('/credentials') ? apiError(501, 'client_credentials_unavailable', 'Client credentials are not available with this storage plugin') : { status: 200, body: client('abc') })
    tabTo('Credentials')
    await flushPromises()
    expect(wrapper.text()).toContain('does not support client credentials')
    expect(wrapper.find('#cred-pem').exists()).toBe(false)
    wrapper.unmount()
  })
})

describe('Authentication settings', () => {
  it('choosing Private Key JWT sends token_endpoint_auth_method null and the chosen keys', async () => {
    const list = [cred('one')]
    const { wrapper, calls } = await mountAt(Detail, path, (c) => c.method === 'PATCH' ? { status: 200, body: client('abc') } : server(list)(c))
    tabTo('Advanced')
    await flushPromises()
    await wrapper.find('#app-auth-method').setValue('private_key_jwt')
    await wrapper.find('[data-testid="pkj-keys"] input').setValue(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const patch = calls.find((c) => c.method === 'PATCH')!.body as Record<string, unknown>
    expect(patch.token_endpoint_auth_method).toBeNull()
    expect(patch.client_authentication_methods).toEqual({ private_key_jwt: { credentials: [{ id: 'one' }] } })
    wrapper.unmount()
  })

  it('needs a key for Private Key JWT', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, server([]))
    tabTo('Advanced')
    await flushPromises()
    await wrapper.find('#app-auth-method').setValue('private_key_jwt')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('Choose at least one key')
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false)
    wrapper.unmount()
  })

  it('reverting clears client_authentication_methods and sets a method', async () => {
    const pkj = client('abc', { token_endpoint_auth_method: null, client_authentication_methods: { private_key_jwt: { credentials: [{ id: 'one' }] } } })
    const { wrapper, calls } = await mountAt(Detail, path, (c) => c.url.endsWith('/credentials') ? { status: 200, body: [cred('one')] } : { status: 200, body: pkj })
    tabTo('Advanced')
    await flushPromises()
    expect((wrapper.find('#app-auth-method').element as HTMLSelectElement).value).toBe('private_key_jwt')
    await wrapper.find('#app-auth-method').setValue('client_secret_basic')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'PATCH')!.body).toMatchObject({ client_authentication_methods: null, token_endpoint_auth_method: 'client_secret_basic' })
    wrapper.unmount()
  })

  it('sends the JAR and token exchange settings only when changed, and blocks the exchange toggle for third-party applications', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, (c) => c.method === 'PATCH' ? { status: 200, body: client('abc') } : server([cred('one')])(c))
    tabTo('Advanced')
    await flushPromises()
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const plain = calls.find((c) => c.method === 'PATCH')!.body as Record<string, unknown>
    expect(plain).not.toHaveProperty('signed_request_object')
    expect(plain).not.toHaveProperty('token_exchange')
    const boxes = wrapper.findAll('fieldset input[type="checkbox"]')
    const required = boxes.find((b) => b.element.parentElement?.textContent?.includes('Require a signed request object'))!
    await required.setValue(true)
    const exchange = wrapper.findAll('input[type="checkbox"]').find((b) => b.element.parentElement?.textContent?.includes('Allow custom token exchange'))!
    await exchange.setValue(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const body = calls.filter((c) => c.method === 'PATCH').at(-1)!.body as Record<string, unknown>
    expect(body.signed_request_object).toEqual({ required: true, credentials: [] })
    expect(body.token_exchange).toEqual({ allow_any_profile_of_type: ['custom_authentication'] })
    wrapper.unmount()
  })

  it('disables the token exchange toggle for a third-party application', async () => {
    const { wrapper } = await mountAt(Detail, path, (c) => c.url.endsWith('/credentials') ? { status: 200, body: [] } : { status: 200, body: client('abc', { is_first_party: false }) })
    tabTo('Advanced')
    await flushPromises()
    const exchange = wrapper.findAll('input[type="checkbox"]').find((b) => b.element.parentElement?.textContent?.includes('Allow custom token exchange'))!
    expect(exchange.attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="exchange-hint"]').text()).toContain('first-party')
    wrapper.unmount()
  })
})
