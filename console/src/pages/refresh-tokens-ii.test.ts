import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { mountAt, confirmPrompt, topDialog } from '../test/mount'
import { client, resourceServer } from '../test/services'
import AppDetail from './applications/Detail.vue'
import ApiDetail from './apis/Detail.vue'
import UserDetail from './users/Detail.vue'
import TenantSettings from './settings/TenantSettings.vue'
import OrgDetail from './organizations/Detail.vue'

afterEach(() => { document.body.innerHTML = '' })

async function tab(name: string) {
  const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role=tab]')).find(x => x.textContent?.trim() === name)
  expect(trigger, `tab ${name}`).toBeTruthy()
  trigger!.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); trigger!.focus(); await flushPromises()
}

const apis = [resourceServer('billing', { scopes: [{ value: 'read:invoices', description: 'Read invoices' }] }), resourceServer('mgmt', { is_system: true, identifier: 'https://acme.example.test/api/v2/' }), resourceServer('operator', { identifier: 'urn:zeroauthy:management' })]

describe('Refresh tokens II console', () => {
  it('edits first-party MRRT policies with API/scope choices and clears an application quota with null', async () => {
    const app = client('abc', { token_quota: { client_credentials: { per_hour: 10, per_day: 50, enforce: true } } } as Partial<ReturnType<typeof client>>)
    const { wrapper, calls } = await mountAt(AppDetail, '/t/acme/applications/abc', c => c.url.includes('/resource-servers') ? { status: 200, body: { resource_servers: apis, total: 3 } } : { status: 200, body: app })
    await tab('Refresh tokens')
    await wrapper.get('[data-testid=mrrt-add]').trigger('click')
    const options = wrapper.get('#mrrt-audience-0').findAll('option').map(x => x.attributes('value'))
    expect(options).toContain('https://api.example.test/billing')
    expect(options).not.toContain('https://acme.example.test/api/v2/')
    expect(options).not.toContain('urn:zeroauthy:management')
    await wrapper.get('#mrrt-audience-0').setValue('https://api.example.test/billing')
    await wrapper.get('#mrrt-scope-0-0').setValue(true)
    await wrapper.get('#app-quota-enabled').setValue(false)
    await wrapper.get('[data-testid=refresh-settings]').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toMatchObject({ refresh_token: { policies: [{ audience: 'https://api.example.test/billing', scope: ['read:invoices'] }] }, token_quota: null })
    wrapper.unmount()
  })
  it('hides MRRT for third-party applications and exposes proof requirements without changing other settings', async () => {
    const app = client('abc', { is_first_party: false })
    const { wrapper, calls } = await mountAt(AppDetail, '/t/acme/applications/abc', () => ({ status: 200, body: app }))
    await tab('Refresh tokens')
    expect(wrapper.find('[data-testid=mrrt-editor]').exists()).toBe(false)
    await wrapper.get('#app-require-proof').setValue(true)
    await wrapper.get('[data-testid=refresh-settings]').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toMatchObject({ require_proof_of_possession: true })
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).not.toHaveProperty('refresh_token.policies')
    wrapper.unmount()
  })
  it('saves online access and DPoP policy for a custom API and can clear it', async () => {
    const api = resourceServer('billing')
    const { wrapper, calls } = await mountAt(ApiDetail, '/t/acme/apis/billing', () => ({ status: 200, body: api }))
    await tab('Settings')
    await wrapper.get('#api-online').setValue(true)
    await wrapper.get('#api-online-ephemeral').setValue(true)
    await wrapper.get('#api-proof-mechanism').setValue('dpop')
    await wrapper.get('#api-proof-required').setValue(true)
    await wrapper.get('#api-proof-for').setValue('public_clients')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toMatchObject({ allow_online_access: true, allow_online_access_with_ephemeral_sessions: true, proof_of_possession: { mechanism: 'dpop', required: true, required_for: 'public_clients' } })
    await wrapper.get('#api-proof-mechanism').setValue('none')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toHaveProperty('proof_of_possession', null)
    wrapper.unmount()
  })
  it('confirms explicit session revoke including offline tokens, shows token device history and edits metadata', async () => {
    const session = { id: 's1', user_id: 'auth0|u1', device: { last_ip: '192.0.2.1' }, clients: [{client_id: 'abc'}], last_interacted_at: '2026-11-18T00:00:00Z', session_metadata: { label: 'browser' } }
    const token = { id: 'rt1', user_id: 'auth0|u1', client_id: 'abc', session_id: 's1', resource_servers: [], device: { initial_ip: '192.0.2.2', last_ip: '192.0.2.3', last_user_agent: 'Example browser' }, last_exchanged_at: '2026-11-18T00:00:00Z', created_at: '2026-11-17T00:00:00Z', refresh_token_metadata: {} }
    const { wrapper, calls } = await mountAt(UserDetail, '/t/acme/users/auth0%7Cu1', c => c.url.includes('/refresh-tokens') ? { status: 200, body: c.method === 'PATCH' ? { ...token, ...(c.body as object) } : { tokens: [token] } } : c.url.includes('/sessions') ? { status: 200, body: c.method === 'GET' ? { sessions: [session] } : { ...session, ...(c.body as object) } } : { status: 200, body: { user_id: 'auth0|u1', email: 'fixture@example.test', identities: [] } })
    await tab('Sessions and devices')
    expect(wrapper.text()).toContain('192.0.2.3')
    for (const [id, field, endpoint] of [['s1', 'session_metadata', '/sessions/s1'], ['rt1', 'refresh_token_metadata', '/refresh-tokens/rt1']]) {
      await wrapper.get(`[data-testid=metadata-${id}]`).trigger('click'); await flushPromises()
      const input = topDialog()!.querySelector('textarea')!
      input.value = '{"label":"updated"}'; input.dispatchEvent(new Event('input')); await flushPromises(); await confirmPrompt()
      expect(calls.filter(c => c.method === 'PATCH').at(-1)).toMatchObject({ url: expect.stringContaining(endpoint), body: { [field!]: { label: 'updated' } } })
    }
    await wrapper.get('[data-testid=revoke-session-s1]').trigger('click'); await flushPromises()
    expect(topDialog()?.textContent).toContain('including offline refresh tokens')
    await confirmPrompt()
    expect(calls.filter(c => c.method === 'POST').at(-1)?.url).toContain('/sessions/s1/revoke')
    wrapper.unmount()
  })
  it('limits MRRT to ten policies and preserves stored unknown API/scope entries', async () => {
    const app = client('abc', { refresh_token: { policies: Array.from({ length: 10 }, (_, i) => ({ audience: 'https://unknown.test/' + i, scope: ['future:scope'] })) } })
    const { wrapper, calls } = await mountAt(AppDetail, '/t/acme/applications/abc', c => c.url.includes('/resource-servers') ? { status: 200, body: { resource_servers: apis, total: 3 } } : { status: 200, body: app })
    await tab('Refresh tokens')
    expect(wrapper.get('[data-testid=mrrt-add]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('#mrrt-audience-0').element).toHaveProperty('value', 'https://unknown.test/0')
    await wrapper.get('[data-testid=refresh-settings]').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toMatchObject({ refresh_token: { policies: app.refresh_token.policies } })
    wrapper.unmount()
  })
  it('saves tenant defaults in one request and confirms clearing both defaults with null', async () => {
    const current = { default_token_quota: { clients: { client_credentials: { enforce: true, per_hour: 10, per_day: 50 } } } }
    const { wrapper, calls } = await mountAt(TenantSettings, '/t/acme/settings', c => ({ status: 200, body: c.method === 'PATCH' ? { ...current, ...(c.body as object) } : current }))
    await tab('Advanced')
    await wrapper.get('#tenant-client-quota-enforce').setValue(false)
    const form = wrapper.get('#tenant-client-quota-enforce').element.closest('form')!
    form.dispatchEvent(new Event('submit')); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').map(c => c.body)).toEqual([{ default_token_quota: { clients: { client_credentials: { enforce: false, per_hour: 10, per_day: 50 } } } }])
    await wrapper.findAll('button').find(b => b.text() === 'Remove all tenant defaults')!.trigger('click'); await flushPromises()
    expect(topDialog()?.textContent).toContain('both application and organization')
    await confirmPrompt()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toEqual({ default_token_quota: null })
    wrapper.unmount()
  })
  it('clears an organization override with null', async () => {
    const org = { id: 'org_fixture', name: 'acme', display_name: 'Acme', third_party_client_access: 'block', token_quota: { client_credentials: { per_hour: 5 } } }
    const { wrapper, calls } = await mountAt(OrgDetail, '/t/acme/organizations/org_fixture', () => ({ status: 200, body: org }))
    await wrapper.get('#organization-quota-enabled').setValue(false)
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toMatchObject({ token_quota: null })
    wrapper.unmount()
  })

})
