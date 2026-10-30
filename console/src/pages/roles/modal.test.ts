import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt, topDialog } from '../../test/mount'
import List from './List.vue'

afterEach(() => {
  document.body.innerHTML = ''
})

const roles = { roles: [{ id: 'rol_1', name: 'Editor', description: '' }], start: 0, limit: 20, total: 1 }

function button(label: string): HTMLButtonElement {
  return Array.from(topDialog()!.querySelectorAll<HTMLButtonElement>('button')).find((b) => b.textContent?.trim() === label || b.getAttribute('aria-label') === label)!
}

it('opens create over the list and leaves only through cancel or the X, never an outside click', async () => {
  const { wrapper, router } = await mountAt(List, '/t/acme/roles/new', () => ({ status: 200, body: roles }))
  expect(wrapper.text()).toContain('Editor') // the list stays behind the modal
  expect(topDialog()!.querySelector('h2')!.textContent).toBe('Create role')
  // The dialog listens for outside presses only after a tick.
  await new Promise((r) => setTimeout(r, 10))
  for (const target of [document.querySelector('.overlay')!, document.body]) {
    target.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true, pointerType: 'mouse' }))
    target.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  }
  await flushPromises()
  expect(router.currentRoute.value.name).toBe('role-new')
  button('Cancel').click()
  await flushPromises()
  expect(router.currentRoute.value.name).toBe('roles')
  expect(topDialog()).toBeUndefined()
  await router.push('/t/acme/roles/new')
  await flushPromises()
  button('Close').click()
  await flushPromises()
  expect(router.currentRoute.value.name).toBe('roles')
  wrapper.unmount()
})

it('reloads the list when an edit modal closes', async () => {
  let name = 'Editor'
  const { wrapper, router, calls } = await mountAt(List, '/t/acme/roles/rol_1', (c) =>
    c.url.includes('/roles/rol_1') ? { status: 200, body: { id: 'rol_1', name, description: '' } } : { status: 200, body: { ...roles, roles: [{ id: 'rol_1', name, description: '' }] } },
  )
  expect(topDialog()!.querySelector('h2')!.textContent).toBe('Editor')
  const lists = () => calls.filter((c) => c.method === 'GET' && !c.url.includes('/roles/rol_1')).length
  const before = lists()
  name = 'Writer'
  await router.push('/t/acme/roles')
  await flushPromises()
  expect(lists()).toBe(before + 1)
  expect(wrapper.text()).toContain('Writer')
  wrapper.unmount()
})
