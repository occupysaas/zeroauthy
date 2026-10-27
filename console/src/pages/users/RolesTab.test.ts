import { defineComponent, h, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { tenant, type Reply } from '../../test/services'
import RolesTab from './RolesTab.vue'

afterEach(() => {
  document.body.innerHTML = ''
})
it('assigns and removes roles through user-role endpoints and pages current assignments', async () => {
  const page = defineComponent({ render: () => h(RolesTab, { tenant: tenant('acme'), user: { user_id: 'auth0|1' } }) })
  let assigned = false
  const { wrapper, calls } = await mountAt(page, '/t/acme/users/auth0%7C1', (c) => {
    if (c.method === 'POST') {
      assigned = true
      return { status: 204 }
    }
    if (c.method === 'DELETE') {
      assigned = false
      return { status: 204 }
    }
    if (new URL(c.url).pathname === '/api/v2/roles')
      return { status: 200, body: { roles: [{ id: 'rol_1', name: 'Editors', description: '' }], total: 1 } }
    return {
      status: 200,
      body: { roles: assigned ? [{ id: 'rol_1', name: 'Editors', description: '' }] : [], total: assigned ? 21 : 0, start: 0, limit: 20 },
    }
  })
  await wrapper.get('#assign-role').setValue('rol_1')
  await wrapper.findAll('form')[1]!.trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ roles: ['rol_1'] })
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Next')!
    .trigger('click')
  await flushPromises()
  expect(calls.at(-1)!.url).toContain('page=1')
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Remove role')!
    .trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'DELETE')!.body).toEqual({ roles: ['rol_1'] })
  wrapper.unmount()
})
it('discards a late assignment response after changing tenant and keeps the new controls usable', async () => {
  const selected = ref(tenant('acme'))
  let finish!: (r: Reply) => void
  const page = defineComponent({ render: () => h(RolesTab, { tenant: selected.value, user: { user_id: 'auth0|1' } }) })
  const { wrapper } = await mountAt(page, '/t/acme/users/auth0%7C1', (c) => {
    if (c.method === 'POST')
      return new Promise((r) => {
        finish = r
      })
    return {
      status: 200,
      body: {
        roles:
          new URL(c.url).pathname === '/api/v2/roles'
            ? [{ id: 'rol_1', name: c.url.includes('acme.example.test') ? 'Old role' : 'New role', description: '' }]
            : [],
        total: 0,
        start: 0,
        limit: 20,
      },
    }
  })
  await wrapper.get('#assign-role').setValue('rol_1')
  await wrapper.findAll('form')[1]!.trigger('submit')
  await flushPromises()
  selected.value = tenant('other')
  await flushPromises()
  finish({ status: 204 })
  await flushPromises()
  expect(wrapper.text()).toContain('New role')
  expect(wrapper.text()).not.toContain('Old role')
  await wrapper.get('#assign-role').setValue('rol_1')
  expect(
    wrapper
      .findAll('button')
      .find((b) => b.text() === 'Assign role')!
      .attributes('disabled'),
  ).toBeUndefined()
  wrapper.unmount()
})
