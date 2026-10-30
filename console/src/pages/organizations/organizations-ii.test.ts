import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it, vi } from 'vitest'
import { mountAt } from '../../test/mount'
import { fakeServices, tenant, type Reply, type Call } from '../../test/services'
import { useTenantsStore } from '../../stores/tenants'
import Detail from './Detail.vue'
import List from './List.vue'
const org = { id: 'org_test', name: 'test', display_name: 'Test', third_party_client_access: 'block', is_app_entitlement_active: false }
async function open(name: string, handler: (c: Call) => Reply | Promise<Reply>) {
 const result = await mountAt(Detail, '/t/acme/organizations/org_test', c => c.url.endsWith('/org_test') && c.method === 'GET' ? { status: 200, body: org } : handler(c))
 const trigger = result.wrapper.findAll('[role="tab"]').find(b => b.text() === name); expect(trigger, name).toBeDefined(); await trigger!.trigger('mousedown'); (trigger!.element as HTMLElement).focus(); await flushPromises(); return result
}
async function click(wrapper: Awaited<ReturnType<typeof mountAt>>['wrapper'], text: string) { const b = wrapper.findAll('button').find(b => b.text() === text); expect(b, text).toBeDefined(); await b!.trigger('click'); await flushPromises() }
afterEach(() => { document.body.innerHTML = ''; vi.restoreAllMocks() })
async function fill(wrapper: Awaited<ReturnType<typeof mountAt>>['wrapper']) { for (const [id, value] of [['inviter-name','Operator'],['invitee-email','a@example.test'],['invitation-client','app']]) await wrapper.get('#'+id).setValue(value); await wrapper.get('form').trigger('submit'); await flushPromises() }
it('invitations create and copy URL', async () => {
 const writeText = vi.fn().mockResolvedValue(undefined); Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
 const { wrapper, calls } = await open('Invitations', c => c.method === 'POST' ? { status: 201, body: { id: 'inv_1', invitation_url: 'https://app.test/invite?invitation=secret', expires_at: '2026-11-01' } } : { status: 200, body: { invitations: [], total: 0 } })
 await wrapper.get('#invitation-roles').setValue('rol_a rol_b'); await wrapper.get('#invitation-delivery').setValue(false); await fill(wrapper)
 expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ inviter: { name: 'Operator' }, invitee: { email: 'a@example.test' }, client_id: 'app', roles: ['rol_a','rol_b'], send_invitation_email: false, ttl_sec: 604800 }); expect(writeText).not.toHaveBeenCalled(); await click(wrapper, 'Copy invitation URL'); expect(writeText).toHaveBeenCalledWith('https://app.test/invite?invitation=secret'); expect(JSON.stringify(localStorage)).not.toContain('secret'); wrapper.unmount()
})
it('entitlement gates member apps', async () => {
 const { wrapper, calls } = await open('Applications', () => ({ status: 200, body: { clients: [] } })); expect(wrapper.text()).toContain('Member application access is not enforced'); await wrapper.get('#organization-entitlement').setValue(true); await click(wrapper, 'Save entitlement'); expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ is_app_entitlement_active: true }); await wrapper.get('#organization-client').setValue('app'); await wrapper.get('form').trigger('submit'); await flushPromises(); expect(calls.find(c => c.method === 'POST')!.body).toEqual({ clients: [{ client_id: 'app', use_for_member_access: true }] }); wrapper.unmount()
})
it('domain attestation is explicit', async () => {
 const { wrapper, calls } = await open('Discovery Domains', () => ({ status: 200, body: { domains: [{ id: 'dom_1', domain: 'example.test', status: 'pending', verification_host: '_organization.example.test', verification_txt: 'verify', use_for_organization_discovery: true }] } })); await click(wrapper, 'Attest verified'); expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0); expect(document.body.textContent).toContain('administrator attestation'); const confirm = document.body.querySelector<HTMLButtonElement>('[role="dialog"] button[data-attest]'); expect(confirm).not.toBeNull(); confirm!.click(); await flushPromises(); expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ status: 'verified' }); wrapper.unmount()
})
it('stale invitation reply is ignored', async () => {
 let resolve!: (reply: Reply) => void
 const { wrapper, router } = await open('Invitations', c => c.method === 'POST' ? new Promise(r => { resolve = r }) : { status: 200, body: { invitations: [], total: 0 } }); await fill(wrapper); await router.push('/t/system/organizations/org_new'); await flushPromises(); resolve({ status: 201, body: { invitation_url: 'https://obsolete.test/secret' } }); await flushPromises(); expect(wrapper.text()).not.toContain('obsolete'); expect(router.currentRoute.value.params.tenant).toBe('system'); wrapper.unmount()
})
it('legacy plugin capabilities are truthful', async () => {
 const { wrapper, calls } = await open('Invitations', () => ({ status: 501, body: { errorCode: 'organizations_ii_unavailable', message: 'Feature unavailable' } })); expect(wrapper.text()).toContain('Feature unavailable'); expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined(); await wrapper.get('form').trigger('submit'); await flushPromises(); expect(calls.filter(c => c.method === 'POST')).toHaveLength(0); wrapper.unmount()
})
it('search resets cursor', async () => {
 const { wrapper, calls } = await mountAt(List, '/t/acme/organizations', () => ({ status: 200, body: { organizations: [org], next: 'cursor1' } })); await click(wrapper,'Next'); expect(new URL(calls.at(-1)!.url).searchParams.get('from')).toBe('cursor1'); await wrapper.get('#organization-filter').setValue('name:new'); await flushPromises(); expect(new URL(calls.at(-1)!.url).pathname).toBe('/api/v2/organizations/search'); expect(new URL(calls.at(-1)!.url).searchParams.get('q')).toBe('name:new'); expect(new URL(calls.at(-1)!.url).searchParams.has('from')).toBe(false); wrapper.unmount()
})
it('latest tenant discovery wins', async () => {
 let resolve!: (reply: Reply) => void, count = 0
 const { services } = fakeServices(() => ++count === 1 ? new Promise(r => { resolve = r }) : { status: 200, body: [tenant('fresh')] }); const store = useTenantsStore(); const old = store.load(services.api); await flushPromises(); await store.load(services.api); resolve({ status: 200, body: [tenant('obsolete')] }); await old; expect(store.list.map(t => t.name)).toEqual(['fresh'])
})
it('API grants display scopes and save organization policy', async () => {
 const { wrapper, calls } = await open('API Grants', () => ({ status: 200, body: { client_grants: [{ id: 'cgr_1', client_id: 'app', audience: 'https://api.test', scope: ['read:orders'], organization_usage: 'allow', allow_any_organization: false }], total: 1 } })); expect(wrapper.text()).toContain('read:orders'); await wrapper.get('[data-grant="cgr_1"] select').setValue('require'); await click(wrapper, 'Save policy'); expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ organization_usage: 'require', allow_any_organization: false }); wrapper.unmount()
})
it('legacy search retains the organization list without pretending to filter', async () => {
 const { wrapper } = await mountAt(List, '/t/acme/organizations', c => c.url.includes('/search') ? { status: 501, body: { errorCode: 'organizations_ii_unavailable', message: 'Unavailable' } } : { status: 200, body: { organizations: [org], total: 1 } }); expect(wrapper.text()).toContain('Test'); expect(wrapper.get('#organization-filter').attributes('disabled')).toBeDefined(); expect(wrapper.text()).toContain('Search is unavailable'); wrapper.unmount()
})
it('retries transient capability errors without permanently disabling invitations', async () => {
 let reads = 0
 const { wrapper } = await open('Invitations', () => ++reads === 1 ? { status: 503, body: { message: 'Try again' } } : { status: 200, body: { invitations: [] } }); expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeDefined(); await click(wrapper, 'Try again'); expect(wrapper.get('button[type="submit"]').attributes('disabled')).toBeUndefined(); wrapper.unmount()
})
it('a newer failed tenant discovery clears grants despite an older successful reply', async () => {
 let resolve!: (reply: Reply) => void, count = 0
 const { services } = fakeServices(() => ++count === 1 ? new Promise(r => { resolve = r }) : { status: 403, body: { message: 'No access' } }); const store = useTenantsStore(); store.list = [tenant('before')]; const old = store.load(services.api); await flushPromises(); await store.load(services.api); resolve({ status: 200, body: [tenant('obsolete')] }); await old; expect(store.list).toEqual([]); expect(store.error).toBe('No access')
})
