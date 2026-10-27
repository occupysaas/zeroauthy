import { defineComponent, h, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { resourceServer, tenant, type Reply } from '../../test/services'
import PermissionsTab from './PermissionsTab.vue'
import UserPermissionsTab from '../users/PermissionsTab.vue'

const permission = {
  resource_server_identifier: 'https://api.example.test/r1',
  permission_name: 'read:x',
  resource_server_name: 'Orders',
  description: 'Read orders',
}
afterEach(() => {
  document.body.innerHTML = ''
})
it('groups selectable permissions by API and adds the selected API permission', async () => {
  const page = defineComponent({ render: () => h(PermissionsTab, { tenant: tenant('acme'), roleId: 'rol_1' }) })
  let assigned = false
  const { wrapper, calls } = await mountAt(page, '/t/acme/roles/rol_1', (c) => {
    if (new URL(c.url).pathname === '/api/v2/resource-servers')
      return {
        status: 200,
        body: {
          resource_servers: [resourceServer('r1', { name: 'Orders', scopes: [{ value: 'read:x', description: 'Read orders' }] })],
          total: 1,
        },
      }
    if (c.method === 'POST') {
      assigned = true
      return { status: 201 }
    }
    return { status: 200, body: { permissions: assigned ? [permission] : [], start: 0, limit: 20, total: assigned ? 1 : 0 } }
  })
  await wrapper.get('#permission-api').setValue('https://api.example.test/r1')
  await wrapper.get('#permission-name').setValue('read:x')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
    permissions: [{ resource_server_identifier: 'https://api.example.test/r1', permission_name: 'read:x' }],
  })
  expect(wrapper.text()).toContain('read:x')
  wrapper.unmount()
})
it('shows every permission source and only removes a direct assignment', async () => {
  const page = defineComponent({ render: () => h(UserPermissionsTab, { tenant: tenant('acme'), user: { user_id: 'auth0|1' } }) })
  let direct = true
  const { wrapper, calls } = await mountAt(page, '/t/acme/users/auth0%7C1', (c) => {
    if (new URL(c.url).pathname === '/api/v2/resource-servers') return { status: 200, body: { resource_servers: [], total: 0 } }
    if (c.method === 'DELETE') {
      direct = false
      return { status: 204 }
    }
    return {
      status: 200,
      body: {
        permissions: [
          {
            ...permission,
            sources: [...(direct ? [{ source_type: 'DIRECT' }] : []), { source_type: 'ROLE', source_id: 'rol_1', source_name: 'Editors' }],
          },
        ],
        start: 0,
        limit: 20,
        total: 1,
      },
    }
  })
  expect(wrapper.text()).toContain('Direct assignment')
  expect(wrapper.text()).toContain('Editors')
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Remove direct assignment')!
    .trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'DELETE')!.url).toContain('/users/auth0%7C1/permissions')
  expect(wrapper.text()).toContain('read:x')
  expect(wrapper.text()).toContain('Editors')
  expect(wrapper.findAll('button').some((b) => b.text() === 'Remove direct assignment')).toBe(false)
  wrapper.unmount()
})
it('ignores delayed permission replies after a tenant switch', async () => {
  const selected = ref(tenant('acme'))
  let finish!: (r: Reply) => void
  const page = defineComponent({ render: () => h(PermissionsTab, { tenant: selected.value, roleId: 'rol_1' }) })
  const { wrapper } = await mountAt(page, '/t/acme/roles/rol_1', (c) => {
    if (new URL(c.url).pathname === '/api/v2/resource-servers') return { status: 200, body: { resource_servers: [], total: 0 } }
    if (c.url.includes('acme.example.test'))
      return new Promise((r) => {
        finish = r
      })
    return { status: 200, body: { permissions: [], start: 0, limit: 20, total: 0 } }
  })
  selected.value = tenant('other')
  await flushPromises()
  finish({ status: 200, body: { permissions: [permission], start: 0, limit: 20, total: 1 } })
  await flushPromises()
  expect(wrapper.text()).not.toContain('read:x')
  expect(wrapper.text()).toContain('No permissions assigned')
  wrapper.unmount()
})
