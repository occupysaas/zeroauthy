import { defineComponent, h, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { confirmPrompt, mountAt } from '../../test/mount'
import { tenant, type Call, type Reply } from '../../test/services'
import UserMfa from './UserMfa.vue'
const code = 'ABCD1234EFGH5678IJKL9012'
const methods = [{ id: 'totp|dev_123', type: 'totp', name: 'My app', created_at: '2026-11-01T00:00:00Z', enrolled_at: '2026-11-01T00:00:00Z', last_auth_at: '2026-11-02T00:00:00Z' }]
function respond(c: Call): Reply {
  if(c.method === 'GET') return { status: 200, body: methods }
  if(c.url.endsWith('/recovery-code-regeneration')) return { status: 200, body: { recovery_code: code } }
  if(c.url.endsWith('/enrollments/ticket')) return { status: 200, body: { ticket_url: 'https://secret-ticket', ticket_id: 'secret-ticket' } }
  return { status: 204 }
}
function page(selected = ref(tenant('acme'))) { return defineComponent({ render: () => h(UserMfa, { tenant: selected.value, user: { user_id: 'auth0|1' } }) }) }
async function click(wrapper: Awaited<ReturnType<typeof mountAt>>['wrapper'], id: string) { await wrapper.get(`#${id}`).trigger('click'); await flushPromises() }
afterEach(() => { document.body.innerHTML = '' })
it('lists method type, name, enrolled and last used and deletes one or all with confirmation', async () => {
  const { wrapper, calls } = await mountAt(page(), '/t/acme/users/auth0%7C1', respond)
  expect(wrapper.text()).toContain('My app'); expect(wrapper.text()).toContain('totp')
  expect(wrapper.findAll('time').map(t => t.attributes('datetime'))).toEqual([methods[0]!.enrolled_at, methods[0]!.last_auth_at])
  await click(wrapper, 'delete-method-0'); await confirmPrompt()
  expect(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/authentication-methods/totp%7Cdev_123'))).toBe(true)
  await click(wrapper, 'delete-all-methods'); await confirmPrompt()
  expect(calls.some(c => c.method === 'DELETE' && c.url.endsWith('/authentication-methods'))).toBe(true)
  wrapper.unmount()
})
it('shows regenerated recovery code once, clears it on dismissal and never displays invitation tickets', async () => {
  const { wrapper, calls } = await mountAt(page(), '/t/acme/users/auth0%7C1', respond)
  await click(wrapper, 'regenerate-recovery'); await confirmPrompt()
  expect(document.body.textContent).toContain(code)
  document.querySelector<HTMLButtonElement>('#dismiss-recovery')!.click(); await flushPromises()
  expect(document.body.textContent).not.toContain(code)
  await click(wrapper, 'invalidate-browser'); await confirmPrompt()
  expect(calls.some(c => c.url.endsWith('/multifactor/actions/invalidate-remember-browser'))).toBe(true)
  await click(wrapper, 'invite-mfa')
  expect(calls.at(-1)?.body).toEqual({ user_id: 'auth0|1', send_mail: true })
  expect(document.body.textContent).not.toContain('secret-ticket')
  expect(wrapper.text()).toContain('Invitation sent')
  wrapper.unmount()
})
it.each(['query', 'delete', 'recovery', 'invitation'] as const)('ignores a stale %s response after tenant changes', async kind => {
  const selected = ref(tenant('acme')); let finish!: (r: Reply) => void
  let hold = kind === 'query'
  const { wrapper, calls } = await mountAt(page(selected), '/t/acme/users/auth0%7C1', c => {
    if(c.url.includes('acme.example.test') && (hold && ((kind === 'query' && c.method === 'GET') || c.method !== 'GET'))) return new Promise(r => { finish = r })
    return respond(c)
  })
  hold = true
  if(kind === 'delete') { await click(wrapper, 'delete-all-methods'); await confirmPrompt() }
  if(kind === 'recovery') { await click(wrapper, 'regenerate-recovery'); await confirmPrompt() }
  if(kind === 'invitation') await click(wrapper, 'invite-mfa')
  selected.value = tenant('system'); await flushPromises()
  const count = calls.length
  finish(kind === 'query' ? { status: 200, body: [{ ...methods[0], name: 'Old method' }] } : kind === 'recovery' ? { status: 200, body: { recovery_code: code } } : { status: 204 }); await flushPromises()
  expect(wrapper.text()).not.toContain('Old method'); expect(document.body.textContent).not.toContain(code)
  expect(wrapper.text()).not.toContain('Invitation sent'); expect(calls.length).toBe(count)
  expect(wrapper.find('button:disabled').exists()).toBe(false)
  wrapper.unmount()
})
it('clears a visible recovery code on tenant change and unmount', async () => {
  const selected = ref(tenant('acme'))
  const { wrapper } = await mountAt(page(selected), '/t/acme/users/auth0%7C1', respond)
  await click(wrapper, 'regenerate-recovery'); await confirmPrompt()
  expect(document.body.textContent).toContain(code)
  selected.value = tenant('system'); await flushPromises(); expect(document.body.textContent).not.toContain(code)
  await click(wrapper, 'regenerate-recovery'); await confirmPrompt(); wrapper.unmount(); await flushPromises()
  expect(document.body.textContent).not.toContain(code)
})
it('shows an unavailable notice on mfa_unavailable', async () => {
  const { wrapper } = await mountAt(page(), '/t/acme/users/auth0%7C1', () => ({ status: 501, body: { errorCode: 'mfa_unavailable' } }))
  expect(wrapper.text()).toContain('does not support MFA'); wrapper.unmount()
})
it('clears a recovery code on route navigation and prevents a late navigation reply from redisplaying it', async () => {
  let finish!: (r: Reply) => void, hold = false
  const { wrapper, router } = await mountAt(page(), '/t/acme/users/auth0%7C1', c => hold && c.url.endsWith('/recovery-code-regeneration') ? new Promise(r => { finish = r }) : respond(c))
  await click(wrapper, 'regenerate-recovery'); await confirmPrompt(); expect(document.body.textContent).toContain(code)
  await router.push('/t/acme/users/auth0%7C2'); await flushPromises(); expect(document.body.textContent).not.toContain(code)
  hold = true
  await click(wrapper, 'regenerate-recovery'); await confirmPrompt()
  await router.push('/t/acme/'); await flushPromises()
  finish({ status: 200, body: { recovery_code: code } }); await flushPromises()
  expect(document.body.textContent).not.toContain(code)
  wrapper.unmount()
})
it('drops stale mutation errors after a tenant switch and can send a new tenant invitation', async () => {
  const selected = ref(tenant('acme')); let finish!: (r: Reply) => void
  const { wrapper, calls } = await mountAt(page(selected), '/t/acme/users/auth0%7C1', c => c.method === 'POST' && c.url.includes('acme.example.test') ? new Promise(r => { finish = r }) : respond(c))
  await click(wrapper, 'invite-mfa'); selected.value = tenant('system'); await flushPromises()
  finish({ status: 501, body: { errorCode: 'mfa_unavailable', message: 'Old error' } }); await flushPromises()
  expect(wrapper.text()).not.toContain('does not support MFA'); expect(wrapper.text()).not.toContain('Old error')
  await click(wrapper, 'invite-mfa'); expect(calls.at(-1)?.url).toContain('system.example.test'); expect(wrapper.text()).toContain('Invitation sent')
  wrapper.unmount()
})
it('loads all method pages and retains only public method display fields', async () => {
  const { wrapper, calls } = await mountAt(page(), '/t/acme/users/auth0%7C1', c => ({ status: 200, body: new URL(c.url).searchParams.get('page') === '0' ? { authenticators: Array.from({ length: 100 }, (_, i) => ({ ...methods[0], id: 'id-' + i, name: 'Page one', secret: 'must-not-render' })), total: 101 } : { authenticators: [{ ...methods[0], name: 'Page two' }], total: 101 } }))
  expect(wrapper.findAll('tbody tr')).toHaveLength(101); expect(wrapper.text()).toContain('Page two'); expect(wrapper.html()).not.toContain('must-not-render')
  expect(calls.filter(c => c.method === 'GET')).toHaveLength(2); wrapper.unmount()
})
