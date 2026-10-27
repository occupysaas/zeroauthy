import { defineComponent, h } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { tenant } from '../../test/services'
import UsersTab from './UsersTab.vue'
afterEach(() => {
  document.body.innerHTML = ''
})
it('assigns a user to a role and removes membership through the user roles endpoint', async () => {
  let assigned = false
  const page = defineComponent({ render: () => h(UsersTab, { tenant: tenant('acme'), roleId: 'rol_1' }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/roles/rol_1', (c) => {
    if (c.method === 'POST') {
      assigned = true
      return { status: 200 }
    }
    if (c.method === 'DELETE') {
      assigned = false
      return { status: 204 }
    }
    return {
      status: 200,
      body: {
        users: assigned ? [{ user_id: 'auth0|1', name: 'Alice', email: 'alice@example.test' }] : [],
        start: 0,
        limit: 20,
        total: assigned ? 21 : 0,
      },
    }
  })
  await wrapper.get('#role-user-id').setValue('auth0|1')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ users: ['auth0|1'] })
  expect(wrapper.text()).toContain('Alice')
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Next')!
    .trigger('click')
  await flushPromises()
  expect(calls.at(-1)!.url).toContain('page=1')
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Remove user')!
    .trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'DELETE')!.url).toContain('/users/auth0%7C1/roles')
  expect(calls.find((c) => c.method === 'DELETE')!.body).toEqual({ roles: ['rol_1'] })
  wrapper.unmount()
})
