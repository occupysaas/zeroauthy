import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { apiError, mountAt, topDialog } from '../../test/mount'
import List from './List.vue'
import Create from './Create.vue'
import Detail from './Detail.vue'
const org = { id: 'org_1234567890123456', name: 'acme', display_name: 'Acme', third_party_client_access: 'block', is_app_entitlement_active: false }
export function tab(name: string) {
  const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find(t => t.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true })); trigger.focus()
}
afterEach(() => { document.body.innerHTML = '' })
it('lists and filters a page locally, and paginates', async () => {
  const { wrapper, calls } = await mountAt(List, '/t/acme/organizations', c => ({ status: 200, body: { organizations: [{ ...org, name: new URL(c.url).searchParams.get('page') === '1' ? 'other' : 'acme' }], total: 21 } }))
  expect(wrapper.text()).toContain('acme')
  await wrapper.get('#organization-filter').setValue('absent')
  expect(wrapper.text()).not.toContain('Acme')
  await wrapper.get('#organization-filter').setValue('')
  await wrapper.findAll('button').find(b => b.text() === 'Next')!.trigger('click'); await flushPromises()
  expect(calls.at(-1)!.url).toContain('page=1'); wrapper.unmount()
})
it('creates an organization and associates a conflict with its name', async () => {
  let fail = true
  const { wrapper, router } = await mountAt(Create, '/t/acme/organizations/new', () => fail ? apiError(409, 'conflict', 'Already used') : { status: 201, body: org })
  await wrapper.get('#organization-name').setValue('acme'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(wrapper.get('#organization-name-error').text()).toContain('Already used')
  fail = false; await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(router.currentRoute.value.name).toBe('organization'); wrapper.unmount()
})
it('edits settings, rejects metadata limits, previews branding and deletes', async () => {
  const { wrapper, calls, router } = await mountAt(Detail, '/t/acme/organizations/' + org.id, c => c.method === 'DELETE' ? { status: 204 } : { status: 200, body: org })
  await wrapper.get('#organization-metadata').setValue('{"bad":null}'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(wrapper.text()).toContain('25 keys')
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0)
  await wrapper.get('#organization-metadata').setValue('{"team":"blue"}'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.at(-1)!.body).toMatchObject({ metadata: { team: 'blue' } })
  tab('Branding'); await flushPromises()
  await wrapper.get('#organization-primary').setValue('#123456'); await wrapper.get('#organization-background').setValue('#ffffff')
  expect(wrapper.get('[data-testid="branding-preview"]').attributes('style')).toContain('#123456')
  await wrapper.get('#organization-logo').setValue('http://bad.test/logo'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(wrapper.text()).toContain('HTTPS')
  tab('Settings'); await flushPromises()
  await wrapper.findAll('button').find(b => b.text() === 'Delete organization')!.trigger('click'); await flushPromises()
  const confirm = Array.from(topDialog()!.querySelectorAll<HTMLButtonElement>('button')).find(b => b.textContent?.trim() === 'Delete organization')!
  confirm.click(); await flushPromises()
  expect(router.currentRoute.value.name).toBe('organizations'); wrapper.unmount()
})
