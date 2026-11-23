import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { client } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/abc'
afterEach(() => { document.body.innerHTML = '' })
async function open(extra = {}, name = 'WS-Fed Web App') {
 const result = await mountAt(Detail, path, () => ({ status: 200, body: client('abc', extra) }))
 const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find(t => t.textContent?.trim() === name)!
 expect(trigger).toBeTruthy()
 trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));trigger.focus();await flushPromises()
 return result
}
describe('WS-Fed Web App add-on', () => {
 it('enables the add-on with realm aliases and keeps the SAML add-on', async () => {
  const { wrapper, calls } = await open({ addons: { samlp: { audience: 'urn:sp' } } })
  await wrapper.get('#wsfed-enabled').setValue(true)
  await wrapper.get('#wsfed-aliases').setValue('urn:sharepoint:portal\n\n https://rp.example/ \n')
  await wrapper.get('[data-testid="wsfed-settings"]').trigger('submit');await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ addons: { samlp: { audience: 'urn:sp' }, wsfed: {} }, client_aliases: ['urn:sharepoint:portal', 'https://rp.example/'] })
  wrapper.unmount()
 })
 it('shows the WS-Fed endpoints and disables the add-on with null', async () => {
  const { wrapper, calls } = await open({ addons: { wsfed: {} }, client_aliases: ['urn:rp'] })
  expect((wrapper.get('#wsfed-aliases').element as HTMLTextAreaElement).value).toBe('urn:rp')
  const usage = wrapper.get('[data-testid="wsfed-usage"]').text()
  expect(usage).toContain('/wsfed/abc')
  expect(usage).toContain('/wsfed/FederationMetadata/2007-06/FederationMetadata.xml')
  expect(usage).toContain('urn:rp')
  await wrapper.get('#wsfed-enabled').setValue(false)
  await wrapper.get('[data-testid="wsfed-settings"]').trigger('submit');await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ addons: { wsfed: null }, client_aliases: ['urn:rp'] })
  wrapper.unmount()
 })
 it('the SAML tab keeps an enabled WS-Fed add-on', async () => {
  const { wrapper, calls } = await open({ addons: { wsfed: {} } }, 'SAML2 Web App')
  await wrapper.get('#saml-enabled').setValue(true)
  await wrapper.get('#saml-settings').setValue('{}')
  await wrapper.get('[data-testid="saml-settings"]').trigger('submit');await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ addons: { wsfed: {}, samlp: {} } })
  wrapper.unmount()
 })
})
