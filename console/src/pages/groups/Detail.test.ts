import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import GroupDetail from './Detail.vue'
afterEach(() => {
  document.body.innerHTML = ''
})
it('shows members and assigns and removes group roles', async () => {
  let roles: object[] = []
  const { wrapper, calls } = await mountAt(GroupDetail, '/t/acme/groups/grp_aaaaaaaaaaaaaaaaaaaa', (c) => {
    if (c.url.includes('/members')) return { status: 200, body: { members: [{ id: 'okta|corp|u1', member_type: 'user', created_at: '2026-11-23T00:00:00Z' }] } }
    if (c.url.includes('/roles') && c.method === 'POST') {
      roles = [{ id: 'rol_1', name: 'Reader', description: '' }]
      return { status: 204 }
    }
    if (c.url.includes('/roles') && c.method === 'DELETE') {
      roles = []
      return { status: 204 }
    }
    if (c.url.includes('/roles')) return { status: 200, body: { roles } }
    return { status: 200, body: { id: 'grp_aaaaaaaaaaaaaaaaaaaa', name: 'Engineering', connection_id: 'con_x', tenant_name: 'acme' } }
  })
  expect(wrapper.text()).toContain('okta|corp|u1')
  await wrapper.findAll('[role="tab"]').find((b) => b.text() === 'Roles')!.trigger('mousedown')
  await flushPromises()
  await wrapper.get('#group-role-id').setValue('rol_1')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ roles: ['rol_1'] })
  expect(wrapper.text()).toContain('Reader')
  await wrapper.findAll('button').find((b) => b.text() === 'Remove role')!.trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'DELETE')!.body).toEqual({ roles: ['rol_1'] })
  wrapper.unmount()
})
