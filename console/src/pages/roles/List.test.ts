import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import List from './List.vue'
import Create from './Create.vue'

afterEach(() => {
  document.body.innerHTML = ''
})
it('lists roles, pages through large results and filters by role name', async () => {
  const { wrapper, calls } = await mountAt(List, '/t/acme/roles', (c) => {
    const q = new URL(c.url).searchParams
    return {
      status: 200,
      body: {
        roles: [{ id: 'rol_' + q.get('page'), name: q.get('page') === '1' ? 'Reviewer' : 'Editor', description: 'Tenant role' }],
        start: Number(q.get('page')) * 20,
        limit: 20,
        total: 21,
      },
    }
  })
  expect(wrapper.text()).toContain('Editor')
  await wrapper
    .findAll('button')
    .find((b) => b.text() === 'Next')!
    .trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('Reviewer')
  expect(calls.at(-1)!.url).toContain('page=1')
  await wrapper.get('#role-filter').setValue('review')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)!.url).toContain('name_filter=review')
  expect(calls.at(-1)!.url).toContain('page=0')
  wrapper.unmount()
})
it('keeps a creation draft after a failed write and opens the created role after retry', async () => {
  let fail = true
  const { wrapper, router, calls } = await mountAt(Create, '/t/acme/roles/new', () =>
    fail
      ? { status: 500, body: { message: 'Write uncertain' } }
      : { status: 200, body: { id: 'rol_new', name: 'Editors', description: 'Can edit' } },
  )
  await wrapper.get('#role-name').setValue('Editors')
  await wrapper.get('#role-description').setValue('Can edit')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(wrapper.text()).toContain('Write uncertain')
  expect((wrapper.get('#role-name').element as HTMLInputElement).value).toBe('Editors')
  fail = false
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)!.body).toEqual({ name: 'Editors', description: 'Can edit' })
  expect(router.currentRoute.value.name).toBe('role')
  wrapper.unmount()
})
