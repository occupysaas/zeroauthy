import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import type { Call, Reply } from '../../test/services'
import Mfa from './Mfa.vue'

const names = ['push-notification', 'sms', 'email', 'duo', 'otp', 'webauthn-roaming', 'webauthn-platform', 'recovery-code']
function respond(c: Call): Reply {
  const path = new URL(c.url).pathname
  if(c.method !== 'GET') return { status: 200, body: c.body }
  if (path.endsWith('/guardian/factors')) return { status: 200, body: names.map(name => ({ name, enabled: name === 'otp', trial_expired: false })) }
  if (path.endsWith('/guardian/policies')) return { status: 200, body: [] }
  return { status: 200, body: { flags: {} } }
}
afterEach(() => { document.body.innerHTML = '' })
it('renders eight factors in documented order with runtime and future status labels and saves a toggle', async () => {
  const { wrapper, calls } = await mountAt(Mfa, '/t/acme/mfa', respond)
  expect(wrapper.findAll('[data-factor]').map(row => row.attributes('data-factor'))).toEqual(names)
  expect(wrapper.get('[data-factor="sms"]').text()).toContain('Configure an enabled phone provider')
  expect(wrapper.get('[data-factor="webauthn-roaming"]').text()).toContain('Available at login')
  expect(wrapper.get('[data-factor="duo"]').text()).toContain('Not planned')
  expect(wrapper.get('#factor-sms').attributes('disabled')).toBeDefined()
  await wrapper.get('#factor-email').setValue(true)
  await flushPromises()
  expect(calls.find(c => c.method === 'PUT')?.body).toEqual({ enabled: true })
  wrapper.unmount()
})
it('saves Never, Always and Adaptive policy and both tenant flags, documenting the local 30-day rule', async () => {
  const { wrapper, calls } = await mountAt(Mfa, '/t/acme/mfa', respond)
  for (const [value, body] of [['all-applications', ['all-applications']], ['confidence-score', ['confidence-score']], ['', []]] as const) {
    await wrapper.get(`input[type="radio"][value="${value}"]`).setValue(true)
    await flushPromises()
    expect(calls.at(-1)?.body).toEqual(body)
    expect((wrapper.get(`input[type="radio"][value="${value}"]`).element as HTMLInputElement).checked).toBe(true)
  }
  expect(wrapper.text()).toContain('30 days')
  for (const flag of ['mfa_show_factor_list_on_enrollment', 'customize_mfa_in_postlogin_action']) {
    await wrapper.get(`#${flag}`).setValue(true)
    await flushPromises()
    expect(calls.at(-1)?.body).toEqual(flag === 'customize_mfa_in_postlogin_action' ? { [flag]: true } : { flags: { [flag]: true } })
  }
  wrapper.unmount()
})
it('labels stored settings forms and clears provider credentials immediately after submission', async () => {
  const { wrapper, calls } = await mountAt(Mfa, '/t/acme/mfa', respond)
  expect(wrapper.get('[data-config="sms/providers/twilio"]').text()).toContain('Available at login')
  expect(wrapper.get('[data-config="push-notification/providers/apns"]').text()).toContain('Not available')
  const form = wrapper.get('[data-config="sms/providers/twilio"]')
  await form.get('input[name="auth_token"]').setValue('provider-secret')
  await form.trigger('submit')
  await flushPromises()
  expect(calls.some(c => c.method === 'PUT' && (c.body as Record<string, unknown>).auth_token === 'provider-secret')).toBe(true)
  expect((form.get('input[name="auth_token"]').element as HTMLInputElement).value).toBe('')
  wrapper.unmount()
})
it('discards stale tenant queries, mutations and errors without blocking the new tenant', async () => {
  let finish!: (r: Reply) => void
  const { wrapper, router } = await mountAt(Mfa, '/t/acme/mfa', c => c.method === 'PUT' ? new Promise(r => { finish = r }) : respond(c))
  await wrapper.get('#factor-email').setValue(true)
  await router.push('/t/system/mfa'); await flushPromises()
  finish({ status: 501, body: { errorCode: 'mfa_unavailable', message: 'old tenant failure' } }); await flushPromises()
  expect(wrapper.text()).not.toContain('old tenant failure')
  expect(wrapper.get('#factor-email').attributes('disabled')).toBeUndefined()
  wrapper.unmount()
})
it('shows an explicit unavailable notice for an older store plugin', async () => {
  const { wrapper } = await mountAt(Mfa, '/t/acme/mfa', () => ({ status: 501, body: { errorCode: 'mfa_unavailable' } }))
  expect(wrapper.text()).toContain('does not support MFA')
  wrapper.unmount()
})
it('drops an earlier factor query after A→B→A and keeps the latest factor state', async () => {
  let finish!: (r: Reply) => void, first = true
  const { wrapper, router } = await mountAt(Mfa, '/t/acme/mfa', c => {
    if(first && c.url.endsWith('/guardian/factors')) { first = false; return new Promise(r => { finish = r }) }
    return respond(c)
  })
  await router.push('/t/system/mfa'); await flushPromises(); await router.push('/t/acme/mfa'); await flushPromises()
  finish({ status: 200, body: names.map(name => ({ name, enabled: name === 'email' })) }); await flushPromises()
  expect((wrapper.get('#factor-email').element as HTMLInputElement).checked).toBe(false)
  expect((wrapper.get('#factor-otp').element as HTMLInputElement).checked).toBe(true)
  wrapper.unmount()
})
it('clears entered provider credentials on tenant switch and ignores an old provider save', async () => {
  let finish!: (r: Reply) => void
  const { wrapper, router, calls } = await mountAt(Mfa, '/t/acme/mfa', c => c.method === 'PUT' ? new Promise(r => { finish = r }) : respond(c))
  const input = () => wrapper.get('[data-config="sms/providers/twilio"] input[name="auth_token"]')
  await input().setValue('old-credential')
  await wrapper.get('[data-config="sms/providers/twilio"]').trigger('submit'); await flushPromises()
  expect((input().element as HTMLInputElement).value).toBe('')
  expect(calls.find(c => c.method === 'PUT')?.url).toContain('acme.example.test')
  await router.push('/t/system/mfa'); await flushPromises()
  await input().setValue('unsaved-new-credential')
  finish({ status: 501, body: { errorCode: 'mfa_unavailable', message: 'old save failure' } }); await flushPromises()
  expect(wrapper.text()).not.toContain('old save failure')
  expect((input().element as HTMLInputElement).value).toBe('unsaved-new-credential')
  await router.push('/t/acme/mfa'); await flushPromises()
  expect((input().element as HTMLInputElement).value).toBe('')
  wrapper.unmount()
})
it('restores the saved policy and tenant flags after rejected writes', async () => {
  const { wrapper } = await mountAt(Mfa, '/t/acme/mfa', c => c.method !== 'GET' ? { status: 400, body: { message: 'Rejected setting' } } : respond(c))
  await wrapper.get('input[type="radio"][value="all-applications"]').setValue(true); await flushPromises()
  expect((wrapper.get('input[type="radio"][value=""]').element as HTMLInputElement).checked).toBe(true)
  await wrapper.get('#mfa_show_factor_list_on_enrollment').setValue(true); await flushPromises()
  expect((wrapper.get('#mfa_show_factor_list_on_enrollment').element as HTMLInputElement).checked).toBe(false)
  await wrapper.get('#customize_mfa_in_postlogin_action').setValue(true); await flushPromises()
  expect((wrapper.get('#customize_mfa_in_postlogin_action').element as HTMLInputElement).checked).toBe(false)
  wrapper.unmount()
})
