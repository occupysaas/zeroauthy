import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt, topDialog } from '../../test/mount'
import Detail from './Detail.vue'

afterEach(() => {
  document.body.innerHTML = ''
})
it('saves role settings and confirms deletion with the current affected user count', async () => {
  const { wrapper, calls, router } = await mountAt(Detail, '/t/acme/roles/rol_1', (c) => {
    if (c.url.includes('/users')) return { status: 200, body: { users: [], total: 42, start: 0, limit: 1 } }
    if (c.method === 'DELETE') return { status: 200 }
    return { status: 200, body: { id: 'rol_1', name: c.method === 'PATCH' ? 'Reviewers' : 'Editors', description: 'A role' } }
  })
  await wrapper.get('#role-name').setValue('Reviewers')
  await wrapper.get('#role-description').setValue('')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'PATCH')!.body).toEqual({ name: 'Reviewers', description: '' })
  expect(wrapper.get('[role="dialog"] h2').text()).toBe('Reviewers')
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Delete role')!
    .trigger('click')
  await flushPromises()
  expect(topDialog()!.textContent).toContain('42 users')
  topDialog()!.querySelector<HTMLButtonElement>('button[type=submit]')!.click()
  await flushPromises()
  expect(router.currentRoute.value.name).toBe('roles')
  wrapper.unmount()
})
