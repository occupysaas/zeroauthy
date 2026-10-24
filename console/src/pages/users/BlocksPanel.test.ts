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
