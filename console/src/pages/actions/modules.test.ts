import { flushPromises, DOMWrapper, type VueWrapper } from '@vue/test-utils'
import type { Component } from 'vue'
import { afterEach, expect, it, vi } from 'vitest'
import { routes } from '../../router'
import { mountAt } from '../../test/mount'
import type { Call, Reply } from '../../test/services'
const module = { id: 'm', name: 'Shared', code: 'module.exports = {}', dependencies: [], secrets: [{ name: 'TOKEN' }], status: 'built', actions_using_module_total: 2, all_changes_published: false, created_at: '', updated_at: '' }
const version = { id: 'v', module_id: 'm', version_number: 1, code: 'old', dependencies: [], secrets: [], created_at: '' }
const ok = (body: unknown): Reply => ({ status: 200, body })
const wrappers: VueWrapper[] = []
async function setup(name: string, path: string, handler: (c: Call) => Reply | Promise<Reply>) {
  const route = routes.find(r => r.name === name)
  expect(route, `${name} route`).toBeDefined()
  const r = await mountAt(route!.component as Component, path, handler); wrappers.push(r.wrapper); return r
}
function click(w: VueWrapper, text: string) { return w.findAll('button').find(b => b.text() === text)!.trigger('click') }
afterEach(() => { wrappers.forEach(w => w.unmount()); wrappers.length = 0; document.body.innerHTML = ''; vi.useRealTimers() })
it('lists modules, creates a draft and navigates to its editor', async () => {
 const { wrapper: w, router, calls } = await setup('action-modules', '/t/acme/actions/modules', c => c.method === 'POST' ? { status: 201, body: module } : ok({ modules: [module], total: 1 }))
 expect(w.text()).toContain('Shared'); await click(w, 'Create module'); await flushPromises()
 await new DOMWrapper(document.querySelector('#module-name')!).setValue('Shared')
 await new DOMWrapper(document.querySelector('form')!).trigger('submit'); await flushPromises()
 expect(calls.find(c => c.method === 'POST')!.body).toMatchObject({ name: 'Shared', code: '' }); expect(router.currentRoute.value.name).toBe('action-module-editor')
})
it('shows 412 module users with a count and Action list', async () => {
 const { wrapper: w } = await setup('action-modules', '/t/acme/actions/modules', c => c.method === 'DELETE' ? { status: 412, body: { message: 'Module in use' } } : c.url.includes('/m/actions') ? ok({ actions: [{ action_id: 'a', action_name: 'Welcome', module_version_number: 1 }], total: 2 }) : ok({ modules: [module], total: 1 }))
 await click(w, 'Delete'); await flushPromises(); await new DOMWrapper(document.querySelector('[data-testid=confirm-delete]')!).trigger('click'); await flushPromises()
 expect(document.body.textContent).toContain('Used by 2 Actions'); expect(document.body.textContent).toContain('Welcome')
})
it('saves module write-only secrets and publishes only a saved built draft', async () => {
 const { wrapper: w, calls } = await setup('action-module-editor', '/t/acme/actions/modules/m', c => c.url.endsWith('/versions') ? ok(version) : ok(module))
 await w.get('#secret-value-0').setValue('hidden'); await click(w, 'Save draft'); await flushPromises()
 expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ secrets: [{ name: 'TOKEN', value: 'hidden' }] })
 expect((w.get('#secret-value-0').element as HTMLInputElement).value).toBe(''); await click(w, 'Publish'); await flushPromises()
 expect(calls.some(c => c.method === 'POST' && c.url.endsWith('/m/versions'))).toBe(true)
})
it('inspects a module version and rolls its draft back', async () => {
 const { wrapper: w, calls } = await setup('action-module-versions', '/t/acme/actions/modules/m/versions', c => new URL(c.url).pathname.endsWith('/versions') ? ok({ versions: [version], total: 1 }) : ok(version))
 await click(w, 'Inspect'); await flushPromises(); expect(w.text()).toContain('Version 1'); await click(w, 'Roll back'); await flushPromises()
 expect(calls.find(c => c.method === 'POST')!.body).toEqual({ module_version_id: 'v' })
})

it('ignores late module reads after a route changes, including A to B to A', async () => {
 let resolve!: (r: Reply) => void
 let reads = 0
 const { wrapper: w, router } = await setup('action-module-editor', '/t/acme/actions/modules/m', () => ++reads === 1 ? new Promise<Reply>(r => { resolve = r }) : ok({ ...module, name: 'Current' }))
 await router.push('/t/acme/actions/modules/b'); await flushPromises(); await router.push('/t/acme/actions/modules/m'); await flushPromises()
 resolve(ok({ ...module, name: 'Stale' })); await flushPromises()
 expect(w.text()).toContain('Current'); expect(w.text()).not.toContain('Stale')
})

it('polls module builds without replacing local edits and disables publishing a dirty or failed draft', async () => {
 vi.useFakeTimers(); let reads = 0
 const { wrapper: w } = await setup('action-module-editor', '/t/acme/actions/modules/m', () => ok({ ...module, status: ++reads === 1 ? 'building' : 'failed', errors: reads === 1 ? [] : ['Build failed'] }))
 await w.get('#action-code').setValue('draft')
 await vi.advanceTimersByTimeAsync(1600); await flushPromises()
 expect(w.text()).toContain('Build failed'); expect((w.get('#action-code').element as HTMLTextAreaElement).value).toBe('draft')
 expect(w.findAll('button').find(b => b.text() === 'Publish')!.attributes('disabled')).toBeDefined()
})
it('validates the module character limit before saving', async () => {
 const { wrapper: w, calls } = await setup('action-module-editor', '/t/acme/actions/modules/m', () => ok(module))
 await w.get('#action-code').setValue('x'.repeat(65537)); await click(w, 'Save draft'); await flushPromises()
 expect(calls.some(c => c.method === 'PATCH')).toBe(false)
})

it('removes an unused module and refreshes the library', async () => {
 let removed = false
 const { wrapper: w, calls } = await setup('action-modules', '/t/acme/actions/modules', c => { if(c.method === 'DELETE') { removed = true; return {status:204} }; return ok({modules:removed ? [] : [module],total:removed ? 0 : 1}) })
 await click(w,'Delete'); await flushPromises(); await new DOMWrapper(document.querySelector('[data-testid=confirm-delete]')!).trigger('click'); await flushPromises()
 expect(calls.some(c => c.method === 'DELETE')).toBe(true); expect(w.text()).toContain('No modules yet.')
})

it.each([204, 412])('ignores a delayed DELETE %s after its modal is closed and replaced', async status => {
 let resolve!: (r: Reply) => void
 const { wrapper: w, calls } = await setup('action-modules', '/t/acme/actions/modules', c => c.method === 'DELETE' ? new Promise<Reply>(r => { resolve = r }) : c.url.includes('/actions?') ? ok({ actions: [], total: 0 }) : ok({ modules: [module, { ...module, id: 'other', name: 'Other' }], total: 2 }))
 await w.findAll('button').find(b => b.text() === 'Delete')!.trigger('click'); await flushPromises()
 await new DOMWrapper(document.querySelector('[data-testid=confirm-delete]')!).trigger('click'); await flushPromises()
 await new DOMWrapper(document.querySelector('[role=dialog]')!).trigger('keydown', { key: 'Escape' }); await flushPromises()
 await w.findAll('button').filter(b => b.text() === 'Delete')[1]!.trigger('click'); await flushPromises()
 resolve({ status, body: status === 412 ? { message: 'In use' } : undefined }); await flushPromises()
 expect(document.querySelector('[role=dialog]')?.textContent).toContain('Delete Other')
 expect(calls.some(c => c.url.includes('/other/actions'))).toBe(false)
 expect(document.querySelector('[data-testid=confirm-delete]')?.hasAttribute('disabled')).toBe(false)
})

it.each([
 ['action-module-editor', '/t/acme/actions/modules/m', true],
 ['action-editor', '/t/acme/actions/a', false],
] as const)('keeps explicit character versus byte code limits in the shared %s lifecycle', async (route, path, saves) => {
 const { wrapper: w, calls } = await setup(route, path, c => c.url.includes('/modules?') ? ok({modules:[],total:0}) : ok({ ...module, modules:[], supported_triggers:[{id:'post-login'}],runtime:'node22' }))
 await w.get('#action-code').setValue('😀'.repeat(40000)); await click(w, 'Save draft'); await flushPromises()
 expect(calls.some(c => c.method === 'PATCH')).toBe(saves)
})
