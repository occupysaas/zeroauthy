import { reactive } from 'vue'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { Api, type SystemTenant } from '../api/client'
import type { Services } from '../context'
import { routes } from '../router'
import { Tenants } from '../tenants'

export function tenant(name: string, extra: Partial<SystemTenant> = {}): SystemTenant {
  return {
    name,
    friendly_name: name,
    domains: [],
    host: name + '.example.test',
    management_api_identifier: `https://${name}.example.test/api/v2/`,
    seeded: false,
    reserved: false,
    created_at: '2026-10-18T00:00:00Z',
    ...extra,
  }
}

export interface Call {
  method: string
  url: string
  body: unknown
}

// fakeServices answers API calls with handler, signed in, with no guards.
export function fakeServices(handler: (c: Call) => { status: number; body?: unknown }) {
  const calls: Call[] = []
  const fetchFn = async (url: RequestInfo | URL, init?: RequestInit) => {
    const c = { method: init?.method ?? 'GET', url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(c)
    const r = handler(c)
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), { status: r.status })
  }
  const api = new Api('https://admin.example.test', async () => 'token', fetchFn as typeof fetch)
  const auth = {
    user: reactive({ authenticated: true, email: 'op@example.test', sub: 'auth0|op' }),
    login: async () => undefined,
    logout: () => undefined,
    accessToken: async () => 'token',
  }
  const services = { auth, api, tenants: new Tenants(api) } as unknown as Services
  return { services, calls }
}

export function memoryRouter(): Router {
  return createRouter({ history: createMemoryHistory('/admin/'), routes })
}

export function client(id: string, extra: Partial<import('../api/client').Client> = {}): import('../api/client').Client {
  return {
    tenant: 'acme',
    client_id: id,
    name: 'App ' + id,
    app_type: 'regular_web',
    is_first_party: true,
    oidc_conformant: true,
    callbacks: [],
    allowed_logout_urls: [],
    web_origins: [],
    allowed_origins: [],
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    token_endpoint_auth_method: 'client_secret_post',
    jwt_configuration: { alg: 'RS256', lifetime_in_seconds: 36000 },
    refresh_token: { rotation_type: 'non-rotating', expiration_type: 'non-expiring' },
    global: false,
    callback_url_template: false,
    require_pushed_authorization_requests: false,
    client_secret: 'S'.repeat(64),
    ...extra,
  }
}
