import { afterEach, expect, it } from 'vitest'
import { flushPromises, type VueWrapper } from '@vue/test-utils'
import type { Component } from 'vue'
import { routes } from '../../router'
import { mountAt, apiError, confirmPrompt } from '../../test/mount'
import type { Call, Reply } from '../../test/services'
import { triggerCode, eventTemplates } from '../actions/templates'
const sid = 'est_1234567890123456789012', eid = 'evt_1234567890123456789012'
const stream = (extra = {}) => ({ id: sid, name: 'Changes', status: 'disabled', total_failures: 5001, subscriptions: [{ event_type: 'user.created' }], destination: { type: 'webhook', configuration: { webhook_endpoint: 'https://sink.example.test', webhook_authorization: { method: 'basic', username: 'receiver' } } }, ...extra })
const delivery = () => ({ id: eid, event_stream_id: sid, status: 'failed', event_type: 'user.created', attempts: [{ status: 'failed', timestamp: '2026-11-01T01:00:00Z', error_message: 'http_5xx: 503', duration: 12 }], event: { id: eid, type: 'user.created', data: { object: { user_id: 'sample' } } } })
const ok = (body: unknown): Reply => ({ status: 200, body })
const wrappers: VueWrapper[] = []
async function setup(name: string, suffix: string, handler: (c: Call) => Reply | Promise<Reply>) {
 const route = routes.find(r => r.name === name); expect(route, 'Event stream route exists').toBeDefined()
 const r = await mountAt(route!.component as Component, '/t/acme/event-streams' + suffix, handler); wrappers.push(r.wrapper); return r
}
async function click(w: VueWrapper, label: string) { const b = w.findAll('button').find(b => b.text() === label); expect(b, label).toBeDefined(); await b!.trigger('click'); await flushPromises() }
afterEach(() => { wrappers.splice(0).forEach(w => w.unmount()); document.body.innerHTML = '' })
it('lists streams with status and failure count', async () => {
 const { wrapper: w, calls } = await setup('event-streams', '', () => ok({ eventStreams: [stream()], next: 'cursor' }))
 expect(w.text()).toContain('Changes'); expect(w.text()).toContain('Disabled'); expect(w.text()).toContain('5001'); expect(new URL(calls[0]!.url).searchParams.get('take')).toBe('50')
 await click(w, 'Next'); expect(new URL(calls.at(-1)!.url).searchParams.get('from')).toBe('cursor')
})
it.each(['basic', 'bearer', 'custom_header'])('webhook secrets are write-only: %s', async method => {
 const auth = { method, username: 'receiver', header_key: 'X-Token', password: '[REDACTED]', token: '[REDACTED]', header_value: '[REDACTED]' }
 const { wrapper: w, calls } = await setup('event-stream-edit', '/' + sid, () => ok(stream({ destination: { type: 'webhook', configuration: { webhook_endpoint: 'https://sink.example.test', webhook_authorization: auth } } })))
 expect((w.get('#event-secret').element as HTMLInputElement).value).toBe(''); expect(w.get('#event-secret').attributes('type')).toBe('password')
 await w.get('#event-name').setValue('Renamed'); await w.get('form[data-testid=stream-form]').trigger('submit'); await flushPromises()
 const b = calls.find(c => c.method === 'PATCH')!.body; expect(b).toMatchObject({ name: 'Renamed' }); expect(JSON.stringify(b)).not.toMatch(/REDACTED|password|token"|header_value/)
})
it('changing authorization method requires a new secret and explains preservation', async () => {
 const { wrapper: w, calls } = await setup('event-stream-edit', '/' + sid, () => ok(stream()))
 expect(w.text()).toContain('Leave blank'); await w.get('#event-auth').setValue('bearer'); await w.get('form[data-testid=stream-form]').trigger('submit'); await flushPromises()
 expect(w.text()).toContain('Enter a new credential'); expect(calls.some(c => c.method === 'PATCH')).toBe(false)
 await w.get('#event-secret').setValue('replacement'); await w.get('form[data-testid=stream-form]').trigger('submit'); await flushPromises()
 expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ destination: { configuration: { webhook_authorization: { method: 'bearer', token: 'replacement' } } } })
})
it('action picker shows only event-stream actions', async () => {
 const { wrapper: w, calls } = await setup('event-stream-new', '/new', () => ok({ actions: [{ id: 'event-action', name: 'Event action', supported_triggers: [{ id: 'event-stream' }] }, { id: 'login-action', name: 'Login action', supported_triggers: [{ id: 'post-login' }] }], total: 2 }))
 await w.get('#event-destination').setValue('action'); await flushPromises()
 expect(w.get('#event-action').text()).toContain('Event action'); expect(w.get('#event-action').text()).not.toContain('Login action'); expect(calls.some(c => new URL(c.url).searchParams.get('triggerId') === 'event-stream')).toBe(true)
})
it('eventbridge form explains not delivered and prevents enable', async () => {
 const { wrapper: w } = await setup('event-stream-new', '/new', () => ok({ actions: [], total: 0 }))
 await w.get('#event-destination').setValue('eventbridge'); expect(w.text()).toContain('not delivered'); expect(w.get('#event-status').attributes('disabled')).toBeDefined()
 expect(w.find('#event-aws-account').exists()).toBe(true)
})
it('send test event shows attempts', async () => {
 const { wrapper: w, calls } = await setup('event-stream-edit', '/' + sid, c => c.url.endsWith('/test') ? { status: 202, body: { ...delivery(), status: 'success', attempts: [{ status: 'success', timestamp: '2026-11-01T01:00:00Z', duration: 7 }] } } : ok(stream()))
 await w.get('#event-test-type').setValue('user.updated'); await w.get('#event-test-data').setValue('{"object":{"user_id":"sample"}}'); await click(w, 'Send test event')
 expect(calls.find(c => c.url.endsWith('/test'))!.body).toEqual({ event_type: 'user.updated', data: { object: { user_id: 'sample' } } }); expect(w.get('[data-testid=test-result]').text()).toContain('Success'); expect(w.get('[data-testid=test-result]').text()).toContain('7')
})
it('deliveries filter and redeliver one and all matching across pages', async () => {
 const { wrapper: w, calls } = await setup('event-deliveries', '/' + sid + '/deliveries', c => c.method === 'POST' ? { status: 202, body: {} } : c.url.includes('/deliveries/' + eid) ? ok(delivery()) : ok({ deliveries: [delivery()], next: 'next-page' }))
 await w.get('#event-date-from').setValue('2026-11-01T00:00:00Z'); await w.get('#event-filter-type').setValue('user.created'); await w.get('form[data-testid=delivery-filters]').trigger('submit'); await flushPromises()
 const u = new URL(calls.at(-1)!.url); expect(u.searchParams.get('date_from')).toBe('2026-11-01T00:00:00Z'); expect(u.searchParams.get('event_types')).toBe('user.created'); expect(u.searchParams.get('take')).toBe('50')
 await click(w, 'Next'); expect(new URL(calls.at(-1)!.url).searchParams.get('from')).toBe('next-page')
 await click(w, 'Event JSON'); expect(w.get('pre').text()).toContain('sample')
 await click(w, 'Redeliver'); expect(calls.at(-1)!.url).toContain('/redeliver/' + eid); expect(w.text()).toContain('Queued'); expect(w.text()).toContain(eid)
 await click(w, 'Redeliver all matching'); await confirmPrompt()
 expect(calls.at(-1)!.body).toEqual({ date_from: '2026-11-01T00:00:00Z', event_types: ['user.created'] }); expect(w.text()).toContain('queued'); expect(w.text()).not.toContain('delivered successfully')
})
it.each(['2026-11-01T00:00:00.1Z', '2026-11-01T00:00:00+00:00', '2026-02-30T00:00:00Z'])('rejects invalid whole-second UTC filter %s', async date => {
 const { wrapper: w, calls } = await setup('event-deliveries', '/' + sid + '/deliveries', () => ok({ deliveries: [] })); const n = calls.length
 await w.get('#event-date-from').setValue(date); await w.get('form[data-testid=delivery-filters]').trigger('submit'); await flushPromises(); expect(calls).toHaveLength(n); expect(w.text()).toContain('whole seconds')
})
it('redelivery conflict remains visible without inventing success', async () => {
 const { wrapper: w } = await setup('event-deliveries', '/' + sid + '/deliveries', c => c.method === 'POST' ? apiError(409, 'conflict', 'detail') : ok({ deliveries: [delivery()] }))
 await click(w, 'Redeliver'); expect(w.text()).toContain('already queued'); expect(w.text()).not.toContain('detail')
})
it('re-enable error shown above threshold', async () => {
 const { wrapper: w } = await setup('event-streams', '', c => c.method === 'PATCH' ? apiError(400, 'invalid_body', 'Too many failed deliveries') : ok({ eventStreams: [stream()] }))
 await click(w, 'Enable'); expect(w.text()).toContain('Too many failed deliveries'); expect(w.text()).toContain('Disabled')
})
it('enable success is visible', async () => {
 const { wrapper: w } = await setup('event-streams', '', c => ok(c.method === 'PATCH' ? stream({ status: 'enabled' }) : { eventStreams: [stream()] }))
 await click(w, 'Enable'); expect(w.text()).toContain('Enabled'); expect(w.text()).toContain('Stream updated')
})
it('actions editor offers event-stream trigger and supported handler template', () => {
 expect(triggerCode('event-stream')).toContain('exports.onExecuteEventStream'); expect(triggerCode('event-stream')).toContain('event.message'); expect(triggerCode('event-stream')).toContain('event.secrets'); expect(triggerCode('event-stream')).toContain('api.cache'); expect(eventTemplates['event-stream']).toHaveProperty('message')
})
it('tenant switch drops stale replies including ABA', async () => {
 let resolve!: (r: Reply) => void, n = 0
 const { wrapper: w, router } = await setup('event-streams', '', () => ++n === 1 ? new Promise<Reply>(r => { resolve = r }) : ok({ eventStreams: [stream({ name: 'Current tenant' })] }))
 await router.push('/t/system/event-streams'); await flushPromises(); await router.push('/t/acme/event-streams'); await flushPromises(); resolve(ok({ eventStreams: [stream({ name: 'Stale tenant' })] })); await flushPromises()
 expect(w.text()).toContain('Current tenant'); expect(w.text()).not.toContain('Stale tenant')
})
it('stale save cannot navigate or show old errors after tenant switch', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('event-stream-edit', '/' + sid, c => c.method === 'PATCH' ? new Promise<Reply>(r => { resolve = r }) : ok(stream()))
 await w.get('form[data-testid=stream-form]').trigger('submit'); await flushPromises(); await router.push('/t/system/event-streams/' + sid); await flushPromises(); resolve(apiError(400, 'bad', 'Old tenant error')); await flushPromises()
 expect(router.currentRoute.value.params.tenant).toBe('system'); expect(w.text()).not.toContain('Old tenant error')
})
it('events unavailable plugin shows notice', async () => {
 const { wrapper: w } = await setup('event-streams', '', () => apiError(501, 'events_unavailable', 'Internal plugin detail'))
 expect(w.text()).toContain('storage provider'); expect(w.text()).not.toContain('Internal plugin detail')
})
it('Action creation offers the event-stream trigger and correct handler', async () => {
 const page = routes.find(r => r.name === 'actions')!.component as Component
 const { wrapper: w, calls } = await mountAt(page, '/t/acme/actions', c => c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'event-stream', version: 'v1' }] }) : c.method === 'POST' ? { status: 201, body: { id: 'action-new' } } : ok({ actions: [], total: 0 })); wrappers.push(w)
 await click(w, 'Create Action'); await flushPromises()
 const trigger = document.querySelector<HTMLSelectElement>('#action-trigger')!; expect(trigger.textContent).toContain('event-stream'); trigger.value = 'event-stream'; trigger.dispatchEvent(new Event('change', { bubbles: true }))
 const name = document.querySelector<HTMLInputElement>('#action-name')!; name.value = 'Receiver'; name.dispatchEvent(new Event('input', { bubbles: true })); await flushPromises()
 document.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await flushPromises()
 expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ supported_triggers: [{ id: 'event-stream' }], code: expect.stringContaining('exports.onExecuteEventStream') })
})
it.each(['basic', 'bearer', 'custom_header'])('creates webhook authorization with explicit write-only %s credential', async method => {
 const { wrapper: w, calls } = await setup('event-stream-new', '/new', () => ({ status: 201, body: stream() }))
 await w.get('#event-name').setValue('New stream'); await w.get('#event-endpoint').setValue('https://sink.example.test'); await w.get('#event-auth').setValue(method)
 if(method === 'basic') await w.get('#event-username').setValue('receiver')
 if(method === 'custom_header') await w.get('#event-header').setValue('X-Token')
 await w.get('#event-secret').setValue('new-value'); await w.get('form[data-testid=stream-form]').trigger('submit'); await flushPromises()
 const key = method === 'basic' ? 'password' : method === 'bearer' ? 'token' : 'header_value'
 expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ name: 'New stream', subscriptions: [{ event_type: 'user.created' }], destination: { type: 'webhook', configuration: { webhook_authorization: { method, [key]: 'new-value' } } } })
})
it('EventBridge edit preserves its immutable configuration', async () => {
 const { wrapper: w, calls } = await setup('event-stream-edit', '/' + sid, () => ok(stream({ destination: { type: 'eventbridge', configuration: { aws_account_id: '123456789012', aws_region: 'us-east-1', aws_partner_event_source: 'partner' } } })))
 expect(w.get('#event-aws-account').attributes('disabled')).toBeDefined(); expect(w.get('#event-status').attributes('disabled')).toBeDefined(); await w.get('#event-name').setValue('Bridge'); await w.get('form[data-testid=stream-form]').trigger('submit'); await flushPromises()
 expect(calls.find(c => c.method === 'PATCH')!.body).toEqual({ name: 'Bridge', status: 'disabled', subscriptions: [{ event_type: 'user.created' }] })
})
it('stale test response cannot reveal attempts in another tenant', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('event-stream-edit', '/' + sid, c => c.url.endsWith('/test') ? new Promise<Reply>(r => { resolve = r }) : ok(stream()))
 await click(w, 'Send test event'); await router.push('/t/system/event-streams/' + sid); await flushPromises(); resolve({ status: 202, body: delivery() }); await flushPromises()
 expect(w.find('[data-testid=test-result]').exists()).toBe(false)
})
it('stale Action picker lookup is ignored', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('event-stream-new', '/new', c => c.url.includes('acme.') ? new Promise<Reply>(r => { resolve = r }) : ok({ actions: [{ id: 'new', name: 'New action', supported_triggers: [{ id: 'event-stream' }] }], total: 1 }))
 await w.get('#event-destination').setValue('action'); await flushPromises(); await router.push('/t/system/event-streams/new'); await flushPromises(); await w.get('#event-destination').setValue('action'); await flushPromises()
 resolve(ok({ actions: [{ id: 'old', name: 'Old action', supported_triggers: [{ id: 'event-stream' }] }], total: 1 })); await flushPromises()
 expect(w.get('#event-action').text()).toContain('New action'); expect(w.get('#event-action').text()).not.toContain('Old action')
})
it('stale delete does not change another tenant list', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router, calls } = await setup('event-streams', '', c => c.method === 'DELETE' ? new Promise<Reply>(r => { resolve = r }) : ok({ eventStreams: [stream({ name: c.url.includes('acme.') ? 'Old stream' : 'New stream' })] }))
 await click(w, 'Delete'); document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.click(); await flushPromises(); await router.push('/t/system/event-streams'); await flushPromises(); resolve({ status: 204 }); await flushPromises()
 expect(w.text()).toContain('New stream'); expect(w.text()).not.toContain('Stream deleted'); expect(calls.filter(c => c.method === 'DELETE')[0]!.url).toContain('acme.example.test')
})
it('stale delivery detail and redelivery results are ignored', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('event-deliveries', '/' + sid + '/deliveries', c => c.url.includes('/deliveries/' + eid) ? new Promise<Reply>(r => { resolve = r }) : ok({ deliveries: [delivery()] }))
 await click(w, 'Event JSON'); await router.push('/t/system/event-streams/' + sid + '/deliveries'); await flushPromises(); resolve(ok(delivery())); await flushPromises(); expect(w.find('pre').exists()).toBe(false)
})
it('stale redelivery acceptance cannot show queued state in another tenant', async () => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, router } = await setup('event-deliveries', '/' + sid + '/deliveries', c => c.method === 'POST' ? new Promise<Reply>(r => { resolve = r }) : ok({ deliveries: [delivery()] }))
 await click(w, 'Redeliver'); await router.push('/t/system/event-streams/' + sid + '/deliveries'); await flushPromises(); resolve({ status: 202 }); await flushPromises(); expect(w.text()).not.toContain('Redelivery queued'); expect(w.text()).not.toContain('Queued')
})
it.each(['event-stream-edit', 'event-deliveries'])('events unavailable notice covers %s', async name => {
 const { wrapper: w } = await setup(name, '/' + sid + (name === 'event-deliveries' ? '/deliveries' : ''), () => apiError(501, 'events_unavailable', 'Internal plugin detail'))
 expect(w.text()).toContain('storage provider'); expect(w.text()).not.toContain('Internal plugin detail')
})
it('refresh permits retry after a queued redelivery fails again', async () => {
 const { wrapper: w } = await setup('event-deliveries', '/' + sid + '/deliveries', c => c.method === 'POST' ? { status: 202 } : ok({ deliveries: [delivery()] }))
 await click(w, 'Redeliver'); expect(w.findAll('button').find(b => b.text() === 'Redeliver')!.attributes('disabled')).toBeDefined()
 await click(w, 'Refresh'); expect(w.findAll('button').find(b => b.text() === 'Redeliver')!.attributes('disabled')).toBeUndefined(); expect(w.text()).not.toContain('Redelivery queued')
})
