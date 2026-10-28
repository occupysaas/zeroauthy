import { DOMWrapper, flushPromises, type VueWrapper } from '@vue/test-utils'
import type { Component } from 'vue'
import { afterEach, expect, it, vi } from 'vitest'
import { routes } from '../../router'
import { mountAt } from '../../test/mount'
import type { Call, Reply } from '../../test/services'

const action = (id = 'a', extra = {}) => ({ id, name: `Action ${id}`, supported_triggers: [{ id: 'post-login' }], code: 'exports.onExecutePostLogin = async () => {};', dependencies: [], secrets: [{ name: 'TOKEN', updated_at: '2026-10-27' }], runtime: 'node22', status: 'built', all_changes_deployed: false, created_at: '2026-10-27', updated_at: '2026-10-27', ...extra })
const version = (id = 'v1') => ({ id, action_id: 'a', number: 1, code: 'old code', dependencies: [], secrets: [], runtime: 'node22', created_at: '2026-10-27', status: 'built' })
const page = (name: string) => (routes.find(r => r.name === name)?.component ?? routes.find(r => r.name === 'actions')!.component) as Component
const ok = (body: unknown): Reply => ({ status: 200, body })
const listing = (actions = [action()]) => ok({ actions, total: actions.length, page: 0, per_page: 100 })
const binding = (id: string) => ({ id, display_name: `Action ${id}`, action: { id, name: `Action ${id}` }, trigger_id: 'post-login', created_at: '', updated_at: '' })
function click(w: VueWrapper, text: string) { return w.findAll('button').find(b => b.text() === text)!.trigger('click') }
const wrappers: VueWrapper[] = []
async function setup(name: string, path: string, handler: (c: Call) => Reply | Promise<Reply>) {
  const r = await mountAt(page(name), path, handler)
  wrappers.push(r.wrapper)
  return r
}
afterEach(() => { wrappers.forEach(w => w.unmount()); wrappers.length = 0; document.body.innerHTML = ''; vi.useRealTimers() })

it('lists and creates Actions for supported triggers', async () => {
  const { wrapper: w, calls, router } = await setup('actions', '/t/acme/actions', c => c.method === 'POST' ? { status: 201, body: action('new') } : c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'post-login' }, { id: 'credentials-exchange' }] }) : listing())
  expect(w.text()).toContain('Action a')
  await click(w, 'Create Action'); await flushPromises()
  await new DOMWrapper(document.querySelector<HTMLInputElement>('#action-name')!).setValue('Welcome')
  await new DOMWrapper(document.querySelector<HTMLSelectElement>('#action-trigger')!).setValue('credentials-exchange')
  await new DOMWrapper(document.querySelector('form')!).trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ name: 'Welcome', supported_triggers: [{ id: 'credentials-exchange' }] })
  expect(router.currentRoute.value.name).toBe('action-editor')
})

it('requires explicit force confirmation after the server refuses deletion of a bound Action', async () => {
  const { wrapper: w, calls } = await setup('actions', '/t/acme/actions', c => c.method === 'DELETE' ? c.url.includes('force=true') ? { status: 204 } : { status: 400, body: { message: 'Action is bound to a trigger' } } : c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'post-login' }] }) : listing())
  await click(w, 'Delete'); await flushPromises()
  const confirm = () => document.querySelector<HTMLButtonElement>('[data-testid=confirm-delete]')!
  confirm().click(); await flushPromises()
  expect(calls.filter(c => c.method === 'DELETE')).toHaveLength(1)
  expect(document.body.textContent).toContain('Force delete')
  expect(confirm().disabled).toBe(true)
  const check = document.querySelector<HTMLInputElement>('#force-delete')!; check.click(); await flushPromises()
  confirm().click(); await flushPromises()
  expect(calls.filter(c => c.method === 'DELETE').at(-1)!.url).toContain('force=true')
})

it('retains a failed draft and requires a server reload before retrying the captured Action', async () => {
  let fail = true
  const { wrapper: w, calls } = await setup('action-editor', '/t/acme/actions/a', c => c.method === 'PATCH' ? fail ? { status: 500, body: { message: 'Write uncertain' } } : ok(action('a', { code: 'my draft' })) : ok(action()))
  await w.get('#action-code').setValue('my draft'); await click(w, 'Save draft'); await flushPromises()
  expect(w.text()).toContain('Write uncertain')
  expect((w.get('#action-code').element as HTMLTextAreaElement).value).toBe('my draft')
  expect(w.findAll('button').find(b => b.text() === 'Save draft')!.attributes('disabled')).toBeDefined()
  fail = false; await click(w, 'Reload before retry'); await flushPromises()
  expect((w.get('#action-code').element as HTMLTextAreaElement).value).toBe('my draft')
  await click(w, 'Save draft'); await flushPromises()
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(2)
})

it('validates exact dependency versions, removes dependencies, and clears write-only secret values after save', async () => {
  const { wrapper: w, calls } = await setup('action-editor', '/t/acme/actions/a', c => ok(action('a', c.method === 'PATCH' ? { dependencies: [{ name: 'uuid', version: '1.2.3' }] } : {})))
  await click(w, 'Add dependency')
  await w.get('#dependency-name-0').setValue('uuid'); await w.get('#dependency-version-0').setValue('^1.2.3')
  await click(w, 'Save draft'); await flushPromises()
  expect(w.text()).toContain('exact version')
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0)
  await w.get('#dependency-version-0').setValue('1.2.3')
  await w.get('#secret-value-0').setValue('hidden-value')
  await click(w, 'Save draft'); await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ secrets: [{ name: 'TOKEN', value: 'hidden-value' }] })
  expect((w.get('#secret-value-0').element as HTMLInputElement).value).toBe('')
  expect(w.html()).not.toContain('hidden-value')
  await click(w, 'Remove dependency'); expect(w.find('#dependency-name-0').exists()).toBe(false)
})

it('polls build status without replacing unsaved code and deploys a built draft', async () => {
  vi.useFakeTimers()
  let reads = 0
  const { wrapper: w, calls } = await setup('action-editor', '/t/acme/actions/a', c => c.method === 'POST' ? { status: 202, body: version() } : ok(action('a', { status: ++reads === 1 ? 'building' : 'built', errors: reads === 1 ? [] : ['Diagnostic'] })))
  await w.get('#action-code').setValue('local code')
  await vi.advanceTimersByTimeAsync(1600); await flushPromises()
  expect(w.text()).toContain('built'); expect(w.text()).toContain('Diagnostic')
  expect((w.get('#action-code').element as HTMLTextAreaElement).value).toBe('local code')
  await w.get('#action-code').setValue(action().code)
  await click(w, 'Deploy'); await flushPromises()
  expect(calls.some(c => c.method === 'POST' && c.url.endsWith('/a/deploy'))).toBe(true)
})

it('loads versions, inspects one and rolls back without overwriting the draft', async () => {
  const { wrapper: w, calls } = await setup('action-versions', '/t/acme/actions/a/versions', c => new URL(c.url).pathname.endsWith('/versions') ? ok({ versions: [version()], total: 1, page: 0, per_page: 100 }) : ok(version()))
  await click(w, 'Inspect'); await flushPromises(); expect((w.get('#version-code').element as HTMLTextAreaElement).value).toBe('old code')
  await click(w, 'Roll back'); await flushPromises()
  expect(calls.find(c => c.method === 'POST')!.body).toEqual({ update_draft: false })
})

it('runs a JSON test and shows masked commands, logs and structured payload errors', async () => {
  const { wrapper: w, calls } = await setup('action-test', '/t/acme/actions/a/test', () => ok({ payload: { commands: [{ type: 'claim', value: '[REDACTED]' }], logs: ['[REDACTED]'], error: { id: 'script_error', message: 'Masked failure [REDACTED]' }, execution_id: 'ex1' } }))
  await w.get('#action-event').setValue('{"user":{"name":"Demo"}}'); await click(w, 'Run test'); await flushPromises()
  expect(calls.at(-1)!.body).toEqual({ payload: { user: { name: 'Demo' } } })
  expect(w.text()).toContain('claim'); expect(w.text()).toContain('[REDACTED]'); expect(w.text()).toContain('script_error'); expect(w.text()).toContain('Masked failure')
})

it('orders trigger bindings with buttons and keyboard and refuses undeployed Actions', async () => {
  const { wrapper: w, calls } = await setup('action-triggers', '/t/acme/actions/triggers/post-login', c => c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'post-login' }] }) : c.url.includes('/bindings') ? ok({ bindings: [binding('a'), binding('b')], total: 2, page: 0, per_page: 100 }) : listing([action('a', { deployed_version: version() }), action('b', { deployed_version: version() }), action('draft')]))
  await w.get('#binding-action').setValue('draft'); await click(w, 'Add binding'); expect(w.text()).toContain('Deploy this Action')
  expect(w.findAll('[data-testid=binding-row]')).toHaveLength(2)
  await w.findAll('[data-testid=binding-row]')[0]!.get('button[aria-label="Move down"]').trigger('click')
  expect(w.findAll('[data-testid=binding-row]')[0]!.text()).toContain('Action b')
  await w.findAll('[data-testid=binding-row]')[0]!.trigger('keydown', { key: 'ArrowDown', altKey: true })
  expect(w.findAll('[data-testid=binding-row]')[0]!.text()).toContain('Action a')
  await click(w, 'Save bindings'); await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ bindings: [{ ref: { type: 'action_id', value: 'a' } }, { ref: { type: 'action_id', value: 'b' } }] })
})

it('looks up an execution ID and displays masked results', async () => {
  const { wrapper: w, calls } = await setup('action-execution', '/t/acme/actions/executions', () => ok({ id: 'ex1', trigger_id: 'post-login', status: 'failed', results: [{ action_name: 'Welcome', error: { id: 'script_error', message: '[REDACTED]' } }], created_at: '', updated_at: '' }))
  await w.get('#execution-id').setValue('ex1'); await click(w, 'Look up'); await flushPromises()
  expect(calls.at(-1)!.url).toContain('/executions/ex1'); expect(w.text()).toContain('Welcome'); expect(w.text()).toContain('[REDACTED]')
})

it('ignores stale editor reads when the route Action changes', async () => {
  let resolve!: (r: Reply) => void
  const { wrapper: w, router } = await setup('action-editor', '/t/acme/actions/a', c => c.url.endsWith('/a') ? new Promise<Reply>(r => { resolve = r }) : ok(action('b')))
  await router.push('/t/acme/actions/b'); await flushPromises()
  resolve(ok(action('a'))); await flushPromises()
  expect((w.get('#action-name').element as HTMLInputElement).value).toBe('Action b')
})

it('discards delayed writes and closes force confirmations when the tenant changes', async () => {
  let resolve!: (r: Reply) => void
  const { wrapper: w, router, calls } = await setup('action-editor', '/t/acme/actions/a', c => c.method === 'PATCH' ? new Promise<Reply>(r => { resolve = r }) : ok(action('a', { name: new URL(c.url).hostname })))
  await w.get('#action-code').setValue('tenant draft'); await click(w, 'Save draft'); await flushPromises()
  await router.push('/t/system/actions/a'); await flushPromises()
  resolve(ok(action('a', { name: 'Old reply' }))); await flushPromises()
  expect((w.get('#action-name').element as HTMLInputElement).value).toBe('system.example.test')
  expect(calls.find(c => c.method === 'PATCH')!.url).toContain('acme.example.test')
})

it('uses the Actions code limit of 100,000 bytes in the existing ScriptEditor', async () => {
  const { wrapper: w } = await setup('action-editor', '/t/acme/actions/a', () => ok(action()))
  await w.get('#action-code').setValue('x'.repeat(80000))
  expect(w.get('[data-testid=action-code-size]').text()).toContain('100000')
  expect(w.get('[data-testid=action-code-size]').text()).not.toContain('exceeds')
})

it('does not offer force deletion for an unrelated validation error', async () => {
  const { wrapper: w } = await setup('actions', '/t/acme/actions', c => c.method === 'DELETE' ? { status: 400, body: { message: 'Invalid Action ID' } } : c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'post-login' }] }) : listing())
  await click(w, 'Delete'); await flushPromises()
  document.querySelector<HTMLButtonElement>('[data-testid=confirm-delete]')!.click(); await flushPromises()
  expect(document.querySelector('#force-delete')).toBeNull()
})

it('closes delete confirmation without sending a write when the tenant changes', async () => {
  const { wrapper: w, router, calls } = await setup('actions', '/t/acme/actions', c => c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'post-login' }] }) : listing())
  await click(w, 'Delete'); await flushPromises()
  expect(document.querySelector('[data-testid=confirm-delete]')).not.toBeNull()
  await router.push('/t/system/actions'); await flushPromises()
  expect(document.querySelector('[data-testid=confirm-delete]')).toBeNull()
  expect(calls.filter(c => c.method === 'DELETE')).toHaveLength(0)
})

it.each([
  ['action-test', '/t/acme/actions/a/test', '#action-event', 'Run test'],
  ['action-execution', '/t/acme/actions/executions', '#execution-id', 'Look up'],
])('ignores stale tenant responses in %s', async (name, path, input, button) => {
  let resolve!: (r: Reply) => void
  const { wrapper: w, router } = await setup(name!, path!, () => new Promise<Reply>(r => { resolve = r }))
  await w.get(input!).setValue(name === 'action-test' ? '{}' : 'old-id')
  await click(w, button!); await flushPromises()
  await router.push(path!.replace('/acme/', '/system/')); await flushPromises()
  resolve(name === 'action-test' ? ok({ payload: { logs: ['old tenant result'] } }) : ok({ id: 'old tenant result', status: 'failed', results: [] })); await flushPromises()
  expect(w.text()).not.toContain('old tenant result')
})

it('cannot clear bindings when their initial read failed, and recovers after retry', async () => {
  let fail = true
  const { wrapper: w, calls } = await setup('action-triggers', '/t/acme/actions/triggers/post-login', c => c.url.endsWith('/triggers') ? ok({ triggers: [{ id: 'post-login' }] }) : c.url.includes('/bindings') ? fail ? { status: 503, body: { message: 'Unavailable' } } : ok({ bindings: [binding('a')], total: 1, page: 0, per_page: 100 }) : listing([action('a', { deployed_version: version() })]))
  const save = w.findAll('button').find(b => b.text() === 'Save bindings')
  if (save) await save.trigger('click')
  await flushPromises()
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0)
  fail = false
  await click(w, 'Try again'); await flushPromises()
  expect(w.findAll('[data-testid=binding-row]')).toHaveLength(1)
  await click(w, 'Save bindings'); await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ bindings: [{ ref: { value: 'a' } }] })
})
