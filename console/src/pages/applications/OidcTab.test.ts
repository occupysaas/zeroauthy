import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { client } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/abc'
afterEach(() => { document.body.innerHTML = '' })
async function open(extra = {}) {
 const result = await mountAt(Detail, path, () => ({ status: 200, body: client('abc', extra) }))
 const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find(t => t.textContent?.trim() === 'OIDC and logout')!
 expect(trigger).toBeTruthy()
 trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));trigger.focus();await flushPromises()
 return result
}
describe('OIDC and logout settings', () => {
 it('keeps the two required initiators selected and saves a single receiver', async () => {
  const { wrapper, calls } = await open()
  for (const name of ['rp-logout', 'idp-logout']) {
   const input = wrapper.get<HTMLInputElement>(`[data-initiator="${name}"]`)
   expect(input.element.checked).toBe(true);expect(input.element.disabled).toBe(true)
  }
  await wrapper.get('#oidc-logout-url').setValue('https://rp.example/logout')
  await wrapper.get('#oidc-initiator-session-revoked').setValue(true)
  await wrapper.get('form').trigger('submit');await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toMatchObject({ oidc_logout: { backchannel_logout_urls: ['https://rp.example/logout'], backchannel_logout_initiators: {mode:'custom', selected_initiators:['rp-logout','idp-logout','session-revoked']} } })
  wrapper.unmount()
 })
 it('refuses a multiline receiver and makes no request', async () => {
  const { wrapper, calls } = await open()
  await wrapper.get('#oidc-logout-url').setValue('https://a.example/logout https://b.example/logout')
  await wrapper.get('form').trigger('submit');await flushPromises()
  expect(calls.filter(c=>c.method==='PATCH')).toHaveLength(0)
  expect(wrapper.text()).toContain('one HTTPS URL')
  wrapper.unmount()
 })
 it('disables HS256 for unavailable secrets and public or private-key clients', async () => {
  for (const extra of [{client_secret:undefined},{app_type:'spa',token_endpoint_auth_method:'none'},{client_authentication_methods:{private_key_jwt:{credentials:[{id:'key'}]}}}]) {
   const {wrapper}=await open(extra)
   expect(wrapper.get<HTMLOptionElement>('#oidc-alg option[value="HS256"]').element.disabled).toBe(true)
   wrapper.unmount()
  }
 })
 it('loads explicit scope restrictions', async () => {
 const {wrapper}=await open({oidc_support:{is_allowed:true,allowed_scopes:['email']}})
 expect(wrapper.get<HTMLInputElement>('#oidc-all-scopes').element.checked).toBe(false)
 expect(wrapper.get<HTMLInputElement>('#oidc-scopes').element.value).toBe('email')
 wrapper.unmount()
 })
 it('saves algorithm and OIDC restrictions without unrelated settings', async () => {
  const {wrapper,calls}=await open({app_type:'regular_web',token_endpoint_auth_method:'client_secret_post'})
  await wrapper.get('#oidc-alg').setValue('HS256')
  await wrapper.get('#oidc-support-configured').setValue(true)
  await wrapper.get('#oidc-all-scopes').setValue(false)
  await wrapper.get('#oidc-scopes').setValue('profile email')
  await wrapper.get('form').trigger('submit');await flushPromises()
  expect(calls.find(c=>c.method==='PATCH')?.body).toEqual({jwt_configuration:{alg:'HS256'},oidc_support:{is_allowed:true,allowed_scopes:['profile','email']}})
  wrapper.unmount()
 })
})
