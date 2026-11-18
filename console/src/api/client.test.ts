import { describe, expect, it } from 'vitest'
import { fakeServices, tenant } from '../test/services'

describe('console Management routing', () => {
  it('sends Management calls for a custom domain to the selected tenant on the system host', async () => {
    const { services: { api }, calls } = fakeServices(() => ({ status: 200, body: {} }))
    const target = tenant('acme', { host: 'login.partner.test', domains: ['login.partner.test'] })
    await api.listClients(target, { page: 1, per_page: 20 })
    await api.updateClient(target, 'encoded/id', { name: 'Updated' })
    expect(calls).toEqual([
      { method: 'GET', url: 'https://admin.example.test/api/console/tenants/acme/api/v2/clients?page=1&per_page=20&include_totals=true&fields=client_secret&include_fields=false', authorization: 'Bearer token', body: undefined, form: undefined },
      { method: 'PATCH', url: 'https://admin.example.test/api/console/tenants/acme/api/v2/clients/encoded%2Fid', authorization: 'Bearer token', body: { name: 'Updated' }, form: undefined },
    ])
  })

  it('keeps Management calls direct on the configured base domain and system origin', async () => {
    const { services: { api }, calls } = fakeServices(() => ({ status: 200, body: {} }))
    await api.getClient(tenant('acme'), 'app')
    await api.getClient(tenant('system', { reserved: true, host: 'admin.example.test' }), 'app')
    expect(calls.map(c => c.url)).toEqual([
      'https://acme.example.test/api/v2/clients/app',
      'https://admin.example.test/api/v2/clients/app',
    ])
  })

  it('uses the proxy for tenant hosts when the deployment has no base domain', async () => {
    const { services: { api }, calls } = fakeServices(() => ({ status: 200, body: {} }), '')
    await api.getClient(tenant('acme'), 'app')
    expect(calls[0]?.url).toBe('https://admin.example.test/api/console/tenants/acme/api/v2/clients/app')
  })
})
