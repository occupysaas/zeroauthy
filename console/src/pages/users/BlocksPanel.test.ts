import { defineComponent, h, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { tenant } from '../../test/services'
import BlocksPanel from './BlocksPanel.vue'
const user = { user_id: 'auth0|abc', blocked: true }
afterEach(() => { document.body.innerHTML = '' })
it('clears automatic blocks through the public user endpoint, reloads and leaves administrative status unchanged', async () => {
  let blocked = true
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: tenant('acme'), user }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/users/auth0%7Cabc', c => {
    if (c.method === 'DELETE') { blocked = false; return { status: 204 } }
    return { status: 200, body: { blocked_for: blocked ? [{ identifier: 'ada@example.test', ip: '192.0.2.1', connection: 'Users' }] : [] } }
  })
  expect(wrapper.text()).toContain('ada@example.test')
  await wrapper.findAll('button').find(x => x.text() === 'Clear login blocks')!.trigger('click'); await flushPromises()
  document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.click(); await flushPromises()
  expect(calls.map(c => c.method)).toEqual(['GET', 'DELETE', 'GET'])
  expect(calls.every(c => c.url.includes('/api/v2/user-blocks/auth0%7Cabc'))).toBe(true)
  expect(wrapper.text()).toContain('No automatic login blocks')
  expect(user.blocked).toBe(true)
  wrapper.unmount()
})
it('checks and clears an IP using anomaly endpoints and treats 404 as unblocked', async () => {
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: tenant('acme') }) })
  let blocked = true
  const { wrapper, calls } = await mountAt(page, '/t/acme/attack-protection', c => {
    if (c.method === 'DELETE') { blocked = false; return { status: 204 } }
    return { status: blocked ? 200 : 404 }
  })
  await wrapper.get('#block-ip').setValue('192.0.2.5')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.findAll('button').find(x => x.text() === 'Clear IP block')!.trigger('click'); await flushPromises()
  document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.click(); await flushPromises()
  expect(calls.map(c => c.method)).toEqual(['GET', 'DELETE', 'GET'])
  expect(calls.every(c => c.url.includes('/api/v2/anomaly/blocks/ips/192.0.2.5'))).toBe(true)
  expect(wrapper.text()).toContain('This IP is not blocked')
  wrapper.unmount()
})

it('ignores a delayed block lookup after switching tenants', async () => {
  const selected = ref(tenant('acme'))
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: selected.value, user }) })
  let finish!: (r: import('../../test/services').Reply) => void
  const { wrapper } = await mountAt(page, '/t/acme/users/auth0%7Cabc', c => c.url.includes('acme.example.test') ? new Promise(r => { finish = r }) : { status: 200, body: { blocked_for: [] } })
  selected.value = tenant('other'); await flushPromises()
  finish({ status: 200, body: { blocked_for: [{ identifier: 'old-tenant@example.test' }] } }); await flushPromises()
  expect(wrapper.text()).not.toContain('old-tenant@example.test')
  expect(wrapper.text()).toContain('No automatic login blocks')
  wrapper.unmount()
})
it('invalidates an IP result and pending confirmation when the address changes', async () => {
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: tenant('acme') }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/attack-protection', () => ({ status: 200 }))
  await wrapper.get('#block-ip').setValue('192.0.2.1')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.get('#block-ip').setValue('192.0.2.2'); await flushPromises()
  expect(wrapper.text()).not.toContain('This IP is blocked')
  expect(wrapper.findAll('button').some(b => b.text() === 'Clear IP block')).toBe(false)
  expect(calls.filter(c => c.method === 'DELETE')).toHaveLength(0)
  wrapper.unmount()
})

it('allows clearing a new IP after dismissing a pending delete and editing the address', async () => {
  let finish!: (r: import('../../test/services').Reply) => void
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: tenant('acme') }) })
  const { wrapper } = await mountAt(page, '/t/acme/attack-protection', c => c.method === 'DELETE' ? new Promise(r => { finish = r }) : { status: 200 })
  await wrapper.get('#block-ip').setValue('192.0.2.1')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.findAll('button').find(b => b.text() === 'Clear IP block')!.trigger('click'); await flushPromises()
  document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.click(); await flushPromises()
  Array.from(document.querySelectorAll<HTMLButtonElement>('[role=dialog] button')).find(b => b.textContent === 'Cancel')!.click(); await flushPromises()
  await wrapper.get('#block-ip').setValue('192.0.2.2')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  const clear = wrapper.findAll('button').find(b => b.text() === 'Clear IP block')!
  expect(clear.attributes('disabled')).toBeUndefined()
  finish({ status: 204 }); await flushPromises()
  expect(wrapper.text()).toContain('192.0.2.2: This IP is blocked')
  expect(clear.attributes('disabled')).toBeUndefined()
  wrapper.unmount()
})

it('refreshing after dismissing a pending user delete restores controls and ignores the old completion', async () => {
  let finish!: (r: import('../../test/services').Reply) => void
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: tenant('acme'), user }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/users/auth0%7Cabc', c => c.method === 'DELETE' ? new Promise(r => { finish = r }) : { status: 200, body: { blocked_for: [{ identifier: 'ada@example.test' }] } })
  await wrapper.findAll('button').find(b => b.text() === 'Clear login blocks')!.trigger('click'); await flushPromises()
  document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.click(); await flushPromises()
  Array.from(document.querySelectorAll<HTMLButtonElement>('[role=dialog] button')).find(b => b.textContent === 'Cancel')!.click(); await flushPromises()
  await wrapper.findAll('button').find(b => b.text() === 'Refresh')!.trigger('click'); await flushPromises()
  const clear = wrapper.findAll('button').find(b => b.text() === 'Clear login blocks')!
  expect(clear.attributes('disabled')).toBeDefined()
  await clear.trigger('click'); await flushPromises()
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(calls.filter(c => c.method === 'DELETE')).toHaveLength(1)
  finish({ status: 204 }); await flushPromises()
  expect(clear.attributes('disabled')).toBeUndefined()
  await clear.trigger('click'); await flushPromises()
  expect(document.querySelector('[role=dialog]')).not.toBeNull()
  expect(document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.disabled).toBe(false)
  expect(calls.map(c => c.method)).toEqual(['GET', 'DELETE', 'GET'])
  wrapper.unmount()
})

it('releases the mutation lock when DELETE settles even if its follow-up lookup is delayed', async () => {
  let finish!: (r: import('../../test/services').Reply) => void
  let gets = 0
  const page = defineComponent({ render: () => h(BlocksPanel, { tenant: tenant('acme') }) })
  const { wrapper } = await mountAt(page, '/t/acme/attack-protection', c => {
    if (c.method === 'DELETE') return { status: 204 }
    if (++gets === 2) return new Promise(r => { finish = r })
    return { status: 200 }
  })
  await wrapper.get('#block-ip').setValue('192.0.2.1')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.findAll('button').find(b => b.text() === 'Clear IP block')!.trigger('click'); await flushPromises()
  document.querySelector<HTMLButtonElement>('[role=dialog] button[type=submit]')!.click(); await flushPromises()
  await wrapper.get('#block-ip').setValue('192.0.2.2')
  await wrapper.get('#block-ip').setValue('192.0.2.1')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(wrapper.findAll('button').find(b => b.text() === 'Clear IP block')!.attributes('disabled')).toBeUndefined()
  finish({ status: 404 }); await flushPromises()
  expect(wrapper.text()).toContain('This IP is blocked')
  wrapper.unmount()
})
