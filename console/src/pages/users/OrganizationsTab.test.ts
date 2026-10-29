import { flushPromises } from '@vue/test-utils'
import { expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import Detail from './Detail.vue'
it('opens the user Organizations tab and links memberships to organization detail', async () => {
  const { wrapper, calls } = await mountAt(Detail, '/t/acme/users/auth0%7Cabc', c => ({ status: 200, body: c.url.includes('/organizations') ? { organizations: [{ id: 'org_1234567890123456', name: 'workspace', display_name: 'Workspace' }], total: 1 } : { user_id: 'auth0|abc', name: 'Member', identities: [] } }))
  const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find(t => t.textContent?.trim() === 'Organizations')!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); trigger.focus(); await flushPromises()
  expect(calls.at(-1)!.url).toContain('/users/auth0%7Cabc/organizations?page=0&per_page=20&include_totals=true')
  expect(wrapper.find('a[href="/admin/t/acme/organizations/org_1234567890123456"]').text()).toBe('Workspace'); wrapper.unmount()
})
