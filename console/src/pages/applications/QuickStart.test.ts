import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import type { Client } from '../../api/client'
import { mountAt } from '../../test/mount'
import { client, clientGrant, resourceServer, type Call } from '../../test/services'
import Detail from './Detail.vue'

const body = () => document.body
const text = () => body().textContent ?? ''
const orders = resourceServer('r1', { name: 'Orders', identifier: 'https://orders.test' })

function backend(c: Client) {
  return (call: Call) => {
    const u = new URL(call.url)
    if (u.pathname.startsWith('/api/v2/clients/')) return { status: 200, body: c }
    if (u.pathname === '/api/v2/client-grants') {
      return { status: 200, body: { client_grants: [clientGrant('g1', c.client_id, orders.identifier)], start: 0, limit: 100, total: 1 } }
    }
    return { status: 404 }
  }
}
function toggle() {
  return body().querySelector<HTMLButtonElement>('[data-testid="reveal"]')!
}

describe('Application quick start', () => {
  afterEach(() => {
    document.body.innerHTML = ''
  })

  it('is the first tab and gives the machine-to-machine curl, with the secret only after reveal', async () => {
    const c = client('m1', { app_type: 'non_interactive', client_secret: 'TOPSECRET' })
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/applications/m1', backend(c))
    expect(body().querySelector('[role="tab"]')!.textContent).toBe('Quick start')
    expect(calls.some((x) => x.url.includes('/client-grants?') && x.url.includes('client_id=m1'))).toBe(true)
    expect(text()).toContain("curl --request POST --url 'https://acme.example.test/oauth/token'")
    expect(text()).toContain("audience=https://orders.test'")
    expect(text()).toContain('YOUR_CLIENT_SECRET')
    expect(text()).not.toContain('TOPSECRET')
    toggle().click()
    await flushPromises()
    expect(text()).toContain("client_secret=TOPSECRET'")
    expect(text()).not.toContain('YOUR_CLIENT_SECRET')
    toggle().click()
    await flushPromises()
    expect(text()).not.toContain('TOPSECRET')
    expect(text()).toContain('Bearer ACCESS_TOKEN')
    expect(text()).not.toContain('can use no connection')
    wrapper.unmount()
  })

  it.each([
    ['with a port and no base domain', { host: 'login.acme.test:8443', domains: ['login.acme.test:8443'] }, 'login.acme.test:8443'],
    ['with a base domain and no port', { host: 'acme.example.test' }, 'acme.example.test'],
  ])('uses the tenant host as the server writes it, %s', async (_n, extra, host) => {
    const c = client('m1', { app_type: 'non_interactive' })
    const { wrapper } = await mountAt(Detail, '/t/acme/applications/m1', backend(c), extra)
    expect(text()).toContain(`--url 'https://${host}/oauth/token'`)
    wrapper.unmount()
  })

  it('tells a machine-to-machine application without grants to authorize an API', async () => {
    const c = client('m1', { app_type: 'non_interactive' })
    const { wrapper } = await mountAt(Detail, '/t/acme/applications/m1', (call) =>
      new URL(call.url).pathname === '/api/v2/client-grants' ? { status: 200, body: { client_grants: [], start: 0, limit: 100, total: 0 } } : backend(c)(call),
    )
    expect(body().querySelector('[data-testid="m2m-empty"]')).not.toBeNull()
    expect(text()).not.toContain('curl')
    wrapper.unmount()
  })

  it('gives a single-page app the authorize URL and the SDK configuration, and says it can use no connection', async () => {
    const c = client('spa1', { app_type: 'spa', token_endpoint_auth_method: 'none', client_secret: undefined, callbacks: ['https://app.test/cb'] })
    const { wrapper } = await mountAt(Detail, '/t/acme/applications/spa1', backend(c))
    expect(text()).toContain('https://acme.example.test/authorize?response_type=code&client_id=spa1&redirect_uri=https%3A%2F%2Fapp.test%2Fcb')
    expect(text()).toContain("domain: 'acme.example.test'")
    expect(text()).toContain("clientId: 'spa1'")
    expect(text()).toContain('authorizationParams')
    expect(body().querySelector('[data-testid="reveal"]')).toBeNull()
    expect(body().querySelector('[data-testid="connections-note"]')!.textContent).toContain('can use no connection')
    wrapper.unmount()
  })

  it('gives a regular web app the nextjs-auth0 and express-openid-connect configuration', async () => {
    const c = client('web1', { client_secret: 'WEBSECRET' })
    const { wrapper } = await mountAt(Detail, '/t/acme/applications/web1', backend(c))
    expect(text()).toContain('AUTH0_DOMAIN=acme.example.test')
    expect(text()).toContain('AUTH0_CLIENT_ID=web1')
    expect(text()).toContain("issuerBaseURL: 'https://acme.example.test'")
    expect(text()).not.toContain('WEBSECRET')
    toggle().click()
    await flushPromises()
    expect(text()).toContain('AUTH0_CLIENT_SECRET=WEBSECRET')
    expect(text()).toContain("clientSecret: 'WEBSECRET'")
    wrapper.unmount()
  })
})
