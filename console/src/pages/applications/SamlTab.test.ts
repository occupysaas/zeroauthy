import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { client } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/abc'
afterEach(() => { document.body.innerHTML = '' })
async function open(extra = {}) {
 const result = await mountAt(Detail, path, () => ({ status: 200, body: client('abc', extra) }))
 const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find(t => t.textContent?.trim() === 'SAML2 Web App')!
 expect(trigger).toBeTruthy()
 trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));trigger.focus();await flushPromises()
 return result
}
describe('SAML2 Web App add-on', () => {
 it('enables the add-on with JSON settings', async () => {
  const { wrapper, calls } = await open()
  await wrapper.get('#saml-enabled').setValue(true)
  await wrapper.get('#saml-settings').setValue('{"audience":"urn:sp","signResponse":true}')
  await wrapper.get('[data-testid="saml-settings"]').trigger('submit');await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ addons: { samlp: { audience: 'urn:sp', signResponse: true } } })
  wrapper.unmount()
 })
 it('shows the IdP endpoints for an enabled add-on and disables it with null', async () => {
  const { wrapper, calls } = await open({ addons: { samlp: { audience: 'urn:sp' } } })
  const usage = wrapper.get('[data-testid="saml-usage"]').text()
  expect(usage).toContain('/samlp/abc')
  expect(usage).toContain('/samlp/metadata/abc')
  expect(usage).toContain('/samlp/abc/logout')
  await wrapper.get('#saml-enabled').setValue(false)
  await wrapper.get('[data-testid="saml-settings"]').trigger('submit');await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ addons: { samlp: null } })
  wrapper.unmount()
 })
 it('refuses settings that are not a JSON object', async () => {
  const { wrapper, calls } = await open()
  await wrapper.get('#saml-enabled').setValue(true)
  for (const bad of ['[1]', 'not json', '"x"']) {
   await wrapper.get('#saml-settings').setValue(bad)
   await wrapper.get('[data-testid="saml-settings"]').trigger('submit');await flushPromises()
  }
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0)
  expect(wrapper.text()).toContain('Enter a JSON object.')
  wrapper.unmount()
 })
})
