import { flushPromises, type VueWrapper } from '@vue/test-utils'
import type { Component } from 'vue'
import { afterEach, expect, it, vi } from 'vitest'
import { routes } from '../router'
import { mountAt } from '../test/mount'
import type { Call, Reply } from '../test/services'

const ok = (body: unknown): Reply => ({ status: 200, body })
const log = (id: string, extra = {}) => ({ log_id: id, type: 's', date: '2026-10-30T12:00:00Z', description: `Event ${id}`, ...extra })
const logs = (items = [log('10')], total = items.length) => ok({ logs: items, total, start: 0, limit: 20, length: items.length })
const execution = (id = 'ex1') => ({ id, trigger_id: 'post-login', status: 'failed', created_at: '2026-10-30T12:00:00Z', results: [{ action_id: 'a1', action_name: 'Welcome', started_at: '', ended_at: '', logs: ['hello [REDACTED]'], error: { id: 'script_error', message: 'Masked failure' } }] })
const stream = (extra = {}) => ({ id: 'st1', name: 'Audit', type: 'http', status: 'paused', sink: { httpEndpoint: 'https://sink.example.test', httpAuthorization: '[REDACTED]', httpCustomHeaders: '[REDACTED]' }, ...extra })
const wrappers: VueWrapper[] = []
async function setup(name: string, path: string, handler: (c: Call) => Reply | Promise<Reply>) {
  const page = ([...routes, ...routes.flatMap(r => r.children || [])].find(r => r.name === name)?.component ?? routes.find(r => r.name === 'logs')!.component) as Component
  const r = await mountAt(page, path, handler); wrappers.push(r.wrapper); return r
}
async function click(w: VueWrapper, text: string) { await w.findAll('button').find(b => b.text() === text)!.trigger('click'); await flushPromises() }
afterEach(() => { wrappers.forEach(w => w.unmount()); wrappers.length = 0; document.body.innerHTML = ''; vi.useRealTimers() })

it('logs search sends q and pages', async () => {
 const { wrapper: w, calls, router } = await setup('logs', '/t/acme/logs', () => logs([log('10')], 43))
 await w.get('#log-q').setValue('type:s'); await w.get('form').trigger('submit'); await flushPromises()
 expect(new URL(calls.at(-1)!.url).searchParams.get('q')).toBe('type:s')
 await click(w, 'Next'); expect(new URL(calls.at(-1)!.url).searchParams.get('page')).toBe('1'); expect(router.currentRoute.value.query.page).toBe('1')
})
it('live mode appends without duplicates', async () => {
 vi.useFakeTimers(); let n = 0
 const { wrapper: w, calls } = await setup('logs', '/t/acme/logs', c => new URL(c.url).searchParams.has('from') ? ok([log('10'), log(String(11 + n++))]) : logs([log('10')]))
 await w.get('#logs-live').setValue(true); await vi.advanceTimersByTimeAsync(4100); await flushPromises()
 expect(w.findAll('[data-testid=log-row]').map(r => r.text()).filter(t => t.includes('Event 10'))).toHaveLength(1)
 expect(w.text()).toContain('Event 11'); expect(calls.some(c => new URL(c.url).searchParams.get('from') === '10')).toBe(true)
})
it('detail links to execution', async () => {
 const { wrapper: w, router } = await setup('log', '/t/acme/logs/10', () => ok(log('10', { details: { actions: { executions: ['ex1'] }, password: '[REDACTED]' } })))
 expect(document.querySelector('[role=dialog]')).not.toBeNull()
 expect(w.get('pre').text()).toContain('[REDACTED]')
 await w.findAll('a').find(a => a.text().includes('ex1'))!.trigger('click'); await flushPromises(); expect(router.currentRoute.value.name).toBe('execution-view'); expect(router.currentRoute.value.params.id).toBe('ex1')
})
it('execution view shows console lines and errors', async () => {
 const { wrapper: w, calls } = await setup('execution-view', '/t/acme/actions/executions/ex1', () => ok(execution()))
 expect(calls[0]!.url).toBe('https://admin.example.test/api/system/tenants/acme/actions/executions/ex1')
 expect(w.text()).toContain('hello [REDACTED]'); expect(w.text()).toContain('Masked failure'); expect(w.text()).toContain('Welcome')
})
it('actions logs filters by trigger and action', async () => {
 const { wrapper: w, calls } = await setup('actions-logs', '/t/acme/actions-logs', () => ok([execution()]))
 await w.get('#execution-trigger').setValue('post-login'); await w.get('#execution-action').setValue('a1'); await w.get('form').trigger('submit'); await flushPromises()
 const u = new URL(calls.at(-1)!.url); expect(u.pathname).toBe('/api/system/tenants/acme/actions/executions'); expect(u.searchParams.get('trigger')).toBe('post-login'); expect(u.searchParams.get('action')).toBe('a1')
 expect(w.text()).toContain('hello [REDACTED]')
})
it('stream secrets are write-only', async () => {
 const { wrapper: w, calls } = await setup('stream-edit', '/t/acme/log-streams/st1', () => ok(stream()))
 expect((w.get('#httpAuthorization').element as HTMLInputElement).value).toBe(''); expect((w.get('#httpCustomHeaders').element as HTMLTextAreaElement).value).toBe('')
 await w.get('#stream-name').setValue('Renamed'); await w.get('form').trigger('submit'); await flushPromises()
 expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ name: 'Renamed', sink: { httpEndpoint: 'https://sink.example.test' } })
 expect(JSON.stringify(calls.find(c => c.method === 'PATCH')!.body)).not.toContain('[REDACTED]')
})
it('cloud stream forms explain not delivered', async () => {
 const { wrapper: w } = await setup('stream-new', '/t/acme/log-streams/new', () => ok([]))
 await w.get('#stream-type').setValue('eventbridge'); expect(w.text()).toContain('not delivered'); expect(w.find('#awsAccountId').exists()).toBe(true)
 await w.get('#stream-type').setValue('eventgrid'); expect(w.text()).toContain('not delivered'); expect(w.find('#azureSubscriptionId').exists()).toBe(true)
})
it('stream resume sends status active', async () => {
 const { wrapper: w, calls } = await setup('log-streams', '/t/acme/log-streams', c => c.method === 'PATCH' ? ok(stream({ status: 'active' })) : ok([stream()]))
 await click(w, 'Resume'); expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ status: 'active' })
})
it('home shows logins and signups', async () => {
 const { wrapper: w, calls } = await setup('home', '/t/acme/', c => c.url.includes('/stats/daily') ? ok([{ date: '2026-10-30T00:00:00Z', logins: 7, signups: 3 }]) : c.url.endsWith('/active-users') ? ok(12) : ok({ total: 2 }))
 expect(w.text()).toContain('Logins'); expect(w.text()).toContain('Signups'); expect(w.get('[data-testid=active-users]').text()).toBe('12')
 expect(w.get('[data-testid=daily-stats]').text()).toContain('7'); expect(w.get('[data-testid=daily-stats]').text()).toContain('3')
 expect(new URL(calls.find(c => c.url.includes('/stats/daily'))!.url).searchParams.has('from')).toBe(true)
})
it('tenant switch drops stale log replies', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('logs', '/t/acme/logs', c => c.url.includes('acme.') ? new Promise<Reply>(r => { resolve = r }) : logs([log('20', { description: 'New tenant' })]))
 await router.push('/t/system/logs'); await flushPromises(); resolve(logs([log('10', { description: 'Old tenant' })])); await flushPromises()
 expect(w.text()).toContain('New tenant'); expect(w.text()).not.toContain('Old tenant')
})
it('logs unavailable plugin shows notice', async () => {
 const { wrapper: w } = await setup('logs', '/t/acme/logs', () => ({ status: 501, body: { errorCode: 'logs_unavailable', message: 'Internal plugin detail' } }))
 expect(w.text()).toContain('storage provider'); expect(w.text()).not.toContain('Internal plugin detail')
})
it('filtered searches explain why live is disabled', async () => {
 const { wrapper: w } = await setup('logs', '/t/acme/logs?q=type:s', () => logs())
 expect(w.get('#logs-live').attributes('disabled')).toBeDefined(); expect(w.text()).toContain('Clear filters')
})
it('live polling stops on unmount and never overlaps a slow request', async () => {
 vi.useFakeTimers(); let resolve!: (r: Reply) => void
 const { wrapper: w, calls } = await setup('logs', '/t/acme/logs', c => new URL(c.url).searchParams.has('take') ? new Promise<Reply>(r => { resolve = r }) : logs())
 await w.get('#logs-live').setValue(true); await vi.advanceTimersByTimeAsync(10000); await flushPromises()
 expect(calls.filter(c => new URL(c.url).searchParams.has('take'))).toHaveLength(1)
 w.unmount(); resolve(ok([log('11')])); await flushPromises(); await vi.advanceTimersByTimeAsync(6000); expect(calls.filter(c => new URL(c.url).searchParams.has('take'))).toHaveLength(1)
})

it.each([
 ['datadog', { datadogRegion: 'eu', datadogApiKey: 'new-secret' }],
 ['splunk', { splunkDomain: 'https://splunk.example.test', splunkPort: '8088', splunkToken: 'new-secret', splunkSecure: true }],
 ['sumo', { sumoSourceAddress: 'https://sumo.example.test/collector' }],
 ['segment', { segmentWriteKey: 'new-secret' }],
 ['mixpanel', { mixpanelRegion: 'eu', mixpanelProjectId: '42', mixpanelServiceAccountUsername: 'service', mixpanelServiceAccountPassword: 'new-secret' }],
 ['eventbridge', { awsAccountId: '123456789012', awsRegion: 'us-east-1' }],
 ['eventgrid', { azureSubscriptionId: '12345678-1234-1234-1234-123456789abc', azureRegion: 'eastus', azureResourceGroup: 'audit' }],
])('creates %s streams with its own sink fields', async (type, sink) => {
 const { wrapper: w, calls } = await setup('stream-new', '/t/acme/log-streams/new', () => ok(stream()))
 await w.get('#stream-type').setValue(type); await w.get('#stream-name').setValue('New stream')
 for(const [key, value] of Object.entries(sink)) await w.get('#'+key).setValue(value)
 await w.get('form').trigger('submit'); await flushPromises()
 expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ type, name: 'New stream', sink })
})
it('stream edit drops stale detail and save replies after tenant navigation', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, calls, router } = await setup('stream-edit', '/t/acme/log-streams/st1', c => c.method === 'PATCH' ? new Promise<Reply>(r => { resolve = r }) : ok(stream({ name: new URL(c.url).hostname })))
 await w.get('#httpAuthorization').setValue('fresh-secret'); await w.get('form').trigger('submit'); await flushPromises()
 await router.push('/t/system/log-streams/st1'); await flushPromises(); resolve(ok(stream({ name: 'Stale saved' }))); await flushPromises()
 expect(router.currentRoute.value.params.tenant).toBe('system'); expect((w.get('#stream-name').element as HTMLInputElement).value).toBe('system.example.test'); expect(w.html()).not.toContain('fresh-secret')
 expect(calls.find(c => c.method === 'PATCH')!.url).toContain('acme.example.test')
})
it('detail drops a delayed response after resource navigation', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('log', '/t/acme/logs/10', c => c.url.endsWith('/10') ? new Promise<Reply>(r => { resolve = r }) : ok(log('20', { description: 'Current detail' })))
 await router.push('/t/acme/logs/20'); await flushPromises(); resolve(ok(log('10', { description: 'Stale detail' }))); await flushPromises()
 expect(w.text()).toContain('Current detail'); expect(w.text()).not.toContain('Stale detail')
})
it('stream filters, PII and startFrom are sent with create and secret inputs clear on success', async () => {
 const { wrapper: w, calls } = await setup('stream-new', '/t/acme/log-streams/new', () => ok(stream()))
 await w.get('#httpEndpoint').setValue('https://sink.example.test'); await w.get('#httpAuthorization').setValue('new-secret'); await w.get('#stream-filter-auth-login-success').setValue(true); await w.get('#pii-email').setValue(true); await w.get('#pii-method').setValue('hash'); await w.get('#stream-start').setValue('2026-10-30T00:00:00Z')
 await w.get('form').trigger('submit'); await flushPromises()
 expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ startFrom: '2026-10-30T00:00:00Z', filters: [{ type: 'category', name: 'auth.login.success' }], pii_config: { log_fields: ['email'], method: 'hash', algorithm: 'xxhash' } }); expect(w.html()).not.toContain('new-secret')
})

it('execution lookup uses the operator route and shows captured console output', async () => {
 const { wrapper: w, calls } = await setup('action-execution', '/t/acme/actions/executions', c => c.url.endsWith('/attempt') ? { status: 204 } : ok(execution()))
 await w.get('#execution-id').setValue('ex1'); await click(w, 'Look up')
 expect(calls.some(c => c.url === 'https://admin.example.test/api/system/tenants/acme/actions/executions/ex1')).toBe(true)
 expect(w.text()).toContain('hello [REDACTED]')
})
it('Actions logs refresh updated results while continuing after the latest cursor', async () => {
 vi.useFakeTimers(); let reads = 0
 const { wrapper: w, calls } = await setup('actions-logs', '/t/acme/actions-logs', c => new URL(c.url).searchParams.has('after') ? ok([]) : ok([{ ...execution(), results: [{ ...execution().results[0], logs: [++reads > 1 ? 'Completed console' : 'Initial console'] }] }]))
 await vi.advanceTimersByTimeAsync(2100); await flushPromises()
 expect(calls.some(c => new URL(c.url).searchParams.get('after') === 'ex1')).toBe(true)
 expect(w.text()).toContain('Completed console'); expect(w.text()).not.toContain('Initial console')
})
it('Actions logs waits for the applied filter before using draft input in polling', async () => {
 vi.useFakeTimers()
 const { wrapper: w, calls } = await setup('actions-logs', '/t/acme/actions-logs?trigger=post-login', () => ok([execution()]))
 await w.get('#execution-trigger').setValue('credentials-exchange'); await vi.advanceTimersByTimeAsync(2100); await flushPromises()
 expect(new URL(calls.at(-1)!.url).searchParams.get('trigger')).toBe('post-login')
})
it('failure filtering uses canonical categories rather than only the f prefix', async () => {
 const { wrapper: w, calls } = await setup('logs', '/t/acme/logs?failures=1', c => new URL(c.url).searchParams.get('page') === '1' ? logs([log('3', { type: 'actions_execution_failed', description: 'Failed Action' })], 101) : logs([log('1', { type: 'organization_access_denied', description: 'Blocked login' }), log('2', { type: 's', description: 'Successful login' })], 101))
 expect(w.text()).toContain('Blocked login'); expect(w.text()).toContain('Failed Action'); expect(w.text()).not.toContain('Successful login'); expect(w.text()).toContain('first 1,000')
 expect(calls).toHaveLength(2)
})
it('failure filtering stops loading old pages after a tenant switch', async () => {
 let resolve!: (r: Reply) => void
 const { calls, router } = await setup('logs', '/t/acme/logs?failures=1', c => c.url.includes('acme.') ? new Promise<Reply>(r => { resolve = r }) : logs([]))
 await router.push('/t/system/logs?failures=1'); await flushPromises(); resolve(logs([log('1', { type: 'f' })], 1000)); await flushPromises()
 expect(calls.filter(c => c.url.includes('acme.'))).toHaveLength(1)
})
it.each([
 ['stream-edit', '/t/acme/log-streams/st1', '/t/system/log-streams/st1', () => ok(stream({ name: 'Current tenant' })), () => ok(stream({ name: 'Stale tenant' }))],
 ['execution-view', '/t/acme/actions/executions/ex1', '/t/system/actions/executions/ex1', () => ok({ ...execution(), status: 'Current tenant' }), () => ok({ ...execution(), status: 'Stale tenant' })],
 ['log-streams', '/t/acme/log-streams', '/t/system/log-streams', () => ok([stream({ name: 'Current tenant' })]), () => ok([stream({ name: 'Stale tenant' })])],
 ['actions-logs', '/t/acme/actions-logs', '/t/system/actions-logs', () => ok([{ ...execution(), status: 'Current tenant' }]), () => ok([{ ...execution(), status: 'Stale tenant' }])],
] as const)('%s drops delayed tenant reads', async (name, path, next, fresh, stale) => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup(name, path, c => c.url.includes('/tenants/acme/') || c.url.includes('acme.') ? new Promise<Reply>(r => { resolve = r }) : fresh())
 await router.push(next); await flushPromises(); resolve(stale()); await flushPromises()
 if(name === 'stream-edit') expect((w.get('#stream-name').element as HTMLInputElement).value).toBe('Current tenant')
 else expect(w.text()).toContain('Current tenant')
 expect(w.text()).not.toContain('Stale tenant')
})
it('Home ignores all delayed tenant statistics', async () => {
 const replies: Array<(r: Reply) => void> = []
 const { wrapper: w, router } = await setup('home', '/t/acme/', c => c.url.includes('acme.') ? new Promise<Reply>(r => { replies.push(r) }) : c.url.includes('/stats/daily') ? ok([{ date: '2026-10-30T00:00:00Z', logins: 2, signups: 1 }]) : c.url.endsWith('/active-users') ? ok(4) : ok({ total: 5 }))
 await router.push('/t/system/'); await flushPromises(); replies[0]!(ok({ total: 999 })); replies[1]!(ok([{ date: '2026-10-30T00:00:00Z', logins: 999, signups: 999 }])); replies[2]!(ok(999)); await flushPromises()
 expect(w.text()).not.toContain('999'); expect(w.get('[data-testid=active-users]').text()).toBe('4')
})
it('Live rejects a delayed poll after a tenant switch and clear filters enables Live', async () => {
 vi.useFakeTimers(); let resolve!: (r: Reply) => void
 const { wrapper: w, router, calls } = await setup('logs', '/t/acme/logs?q=type:s', c => new URL(c.url).searchParams.has('take') ? new Promise<Reply>(r => { resolve = r }) : logs([log('10')]))
 await w.findAll('a').find(a => a.text() === 'Clear filters')!.trigger('click'); await flushPromises(); expect(w.get('#logs-live').attributes('disabled')).toBeUndefined()
 await w.get('#logs-live').setValue(true); await flushPromises(); await router.push('/t/system/logs'); await flushPromises(); resolve(ok([log('99', { description: 'Stale poll' })])); await flushPromises(); await vi.advanceTimersByTimeAsync(4000)
 expect(w.text()).not.toContain('Stale poll'); expect(calls.filter(c => new URL(c.url).searchParams.has('take'))).toHaveLength(1)
})
it('optional public sink placeholders never overwrite configured values', async () => {
 const { wrapper: w, calls } = await setup('stream-edit', '/t/acme/log-streams/st1', () => ok(stream()))
 await w.get('form').trigger('submit'); await flushPromises()
 const sink = (calls.find(c => c.method === 'PATCH')!.body as { sink: Record<string, unknown> }).sink
 expect(sink).toEqual({ httpEndpoint: 'https://sink.example.test' })
})

it('stream list shows persisted delivery health from the operator endpoint', async () => {
 const { wrapper: w, calls } = await setup('log-streams', '/t/acme/log-streams', c => c.url.includes('/api/system/') ? ok([{ id: 'st1', status: 'suspended', last_success_at: '2026-10-30T12:00:00Z', next_at: '2026-10-31T12:00:00Z', failures: 3, last_error_class: 'http_5xx' }]) : ok([stream({ status: 'suspended' })]))
 expect(calls.some(c => c.url === 'https://admin.example.test/api/system/tenants/acme/log-streams/status')).toBe(true)
 expect(w.text()).toContain('2026-10-30T12:00:00Z'); expect(w.text()).toContain('http_5xx'); expect(w.text()).toContain('3 failed attempts'); expect(w.text()).toContain('2026-10-31T12:00:00Z')
})
it('stream list drops delayed health on tenant change and can display health capability notice', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('log-streams', '/t/acme/log-streams', c => c.url.includes('/api/system/tenants/acme/') ? new Promise<Reply>(r => { resolve = r }) : c.url.includes('/api/system/') ? { status: 501, body: { errorCode: 'logs_unavailable', message: 'Private plugin' } } : ok([stream()]))
 await router.push('/t/system/log-streams'); await flushPromises(); resolve(ok([{ id: 'st1', status: 'active', last_success_at: 'STALE_HEALTH', failures: 9, last_error_class: '' }])); await flushPromises()
 expect(w.text()).not.toContain('STALE_HEALTH'); expect(w.text()).not.toContain('Private plugin'); expect(w.text()).toContain('storage provider')
})

it('Actions logs preserves its cursor when the recent-result refresh fails', async () => {
 vi.useFakeTimers(); let newest = 0
 const { calls } = await setup('actions-logs', '/t/acme/actions-logs', c => new URL(c.url).searchParams.has('after') ? ok([execution('ex2')]) : ++newest === 2 ? { status: 503, body: { message: 'Retry refresh' } } : ok([execution()]))
 await vi.advanceTimersByTimeAsync(4100); await flushPromises()
 expect(calls.filter(c => new URL(c.url).searchParams.has('after')).map(c => new URL(c.url).searchParams.get('after'))).toEqual(['ex1', 'ex1'])
})
it('invalid custom header JSON gives a localized form error without sending credentials', async () => {
 const { wrapper: w, calls } = await setup('stream-new', '/t/acme/log-streams/new', () => ok(stream()))
 await w.get('#httpEndpoint').setValue('https://sink.example.test'); await w.get('#httpCustomHeaders').setValue('{broken')
 await w.get('form').trigger('submit'); await flushPromises()
 expect(w.text()).toContain('Custom headers must be a JSON array'); expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
})

it('failure window keeps the applied query while draft search text changes', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, calls } = await setup('logs', '/t/acme/logs?failures=1&q=type:f', c => new URL(c.url).searchParams.get('page') === '0' ? new Promise<Reply>(r => { resolve = r }) : logs([], 101))
 await w.get('#log-q').setValue('type:s'); resolve(logs([log('1', { type: 'f' })], 101)); await flushPromises()
 expect(new URL(calls[1]!.url).searchParams.get('q')).toBe('type:f')
})

it('Actions logs keeps a pending initial result when Live is disabled and schedules no polls', async () => {
 vi.useFakeTimers(); let resolve!: (r: Reply) => void
 const { wrapper: w, calls } = await setup('actions-logs', '/t/acme/actions-logs', () => new Promise<Reply>(r => { resolve = r }))
 expect(w.get('[role=status]').text()).toContain('Loading')
 await w.get('input[type=checkbox]').setValue(false); await flushPromises()
 expect(w.text()).not.toContain('No matching executions')
 expect(w.get('[role=status]').text()).toContain('Loading')
 resolve(ok([execution()])); await flushPromises()
 expect(w.text()).toContain('hello [REDACTED]'); expect(w.find('[role=status]').exists()).toBe(false)
 await vi.advanceTimersByTimeAsync(6000); await flushPromises(); expect(calls).toHaveLength(1)
})
it('Actions logs reenables Live during an initial read without overlapping requests', async () => {
 vi.useFakeTimers(); const replies: Array<(r: Reply) => void> = []
 const { wrapper: w, calls } = await setup('actions-logs', '/t/acme/actions-logs', () => new Promise<Reply>(r => { replies.push(r) }))
 await w.get('input[type=checkbox]').setValue(false); await w.get('input[type=checkbox]').setValue(true); await flushPromises()
 await vi.advanceTimersByTimeAsync(6000); expect(calls).toHaveLength(1)
 replies[0]!(ok([execution()])); await flushPromises(); expect(w.text()).toContain('hello [REDACTED]')
 await vi.advanceTimersByTimeAsync(2000); expect(calls).toHaveLength(2)
 expect(new URL(calls[1]!.url).searchParams.get('after')).toBe('ex1')
 await w.get('input[type=checkbox]').setValue(false); w.unmount(); replies[1]!(ok([execution('stale')])); await flushPromises()
 await vi.advanceTimersByTimeAsync(4000); expect(calls).toHaveLength(2)
})
