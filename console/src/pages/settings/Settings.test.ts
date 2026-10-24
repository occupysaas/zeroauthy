import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountAt, apiError } from '../../test/mount'
import Settings from './TenantSettings.vue'
import AttackProtection from '../attack-protection/AttackProtection.vue'
import type { Reply } from '../../test/services'

afterEach(() => { document.body.innerHTML = '' })
const settings = { friendly_name: 'Acme', picture_url: '', support_email: '', support_url: '', session_lifetime: 168, idle_session_lifetime: 72, ephemeral_session_lifetime: 72, idle_ephemeral_session_lifetime: 24, session_cookie: { mode: 'persistent' }, enabled_locales: ['en', 'fr'], device_flow: { charset: 'base20', mask: '****-****' } }
async function tab(w: Awaited<ReturnType<typeof mountAt>>['wrapper'], name: string) {
  await w.findAll('[role=tab]').find(x => x.text() === name)!.trigger('mousedown')
  await flushPromises()
}
describe('live tenant policy forms', () => {
  it('saves only edited general fields and shows seed overwrite notice', async () => {
    const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', () => ({ status: 200, body: settings }), { seeded: true })
    await wrapper.get('#friendly_name').setValue('New name')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').map(c => c.body)).toEqual([{ friendly_name: 'New name' }])
    expect(wrapper.text()).toContain('seed')
    wrapper.unmount()
  })
  it('labels duration units, preserves nested fields and keeps hosted locales independent', async () => {
    const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', () => ({ status: 200, body: settings }))
    await tab(wrapper, 'Sessions')
    expect(wrapper.text()).toContain('hours')
    await wrapper.get('#session_lifetime').setValue(200)
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.at(-1)?.body).toEqual({ session_lifetime: 200 })
    await tab(wrapper, 'Languages')
    await wrapper.get('#enabled_locales').setValue('fr\nen')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.at(-1)?.body).toEqual({ enabled_locales: ['fr', 'en'] })
    await tab(wrapper, 'Advanced')
    await wrapper.get('#device_flow-mask').setValue('********')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.at(-1)?.body).toEqual({ device_flow: { mask: '********' } })
    wrapper.unmount()
  })
  it('discards dirty forms and ignores delayed saves after a tenant switch', async () => {
    let finish!: (r: Reply) => void
    const { wrapper, router, calls } = await mountAt(Settings, '/t/acme/settings', c => c.method === 'PATCH' ? new Promise(r => { finish = r }) : ({ status: 200, body: { ...settings, friendly_name: new URL(c.url).host } }))
    await wrapper.get('#friendly_name').setValue('Dirty')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    await router.push('/t/system/settings'); await flushPromises()
    finish({ status: 200, body: { ...settings, friendly_name: 'Old response' } }); await flushPromises()
    expect((wrapper.get('#friendly_name').element as HTMLInputElement).value).toBe('system.example.test')
    expect(calls.filter(c => c.method === 'PATCH').every(c => c.url.includes('acme.example.test'))).toBe(true)
    wrapper.unmount()
  })
  it('shows API validation errors at the edited field', async () => {
    const { wrapper } = await mountAt(Settings, '/t/acme/settings', c => c.method === 'PATCH' ? apiError(400, 'invalid_body', 'support_email: invalid email') : { status: 200, body: settings })
    await wrapper.get('#support_email').setValue('bad')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.get('#support_email-error').text()).toContain('invalid email')
    expect(document.activeElement?.id).toBe('support_email')
    wrapper.unmount()
  })
  it('patches only the selected protection feature and shows backend limitations', async () => {
    const { wrapper, calls } = await mountAt(AttackProtection, '/t/acme/attack-protection', () => ({ status: 200, body: { enabled: false, max_attempts: 10 } }))
    await wrapper.get('#max_attempts').setValue(5)
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.at(-1)?.url).toContain('/attack-protection/brute-force-protection')
    expect(calls.at(-1)?.body).toEqual({ max_attempts: 5 })
    expect(wrapper.text()).toContain('notification')
    await tab(wrapper, 'Breached passwords')
    expect(wrapper.text()).toContain('unavailable')
    wrapper.unmount()
  })
  it('omits unchanged provider credentials and clears replacement secrets on success', async () => {
    const captcha = { active_provider_id: 'hcaptcha', hcaptcha: { site_key: 'site' } }
    const { wrapper, calls } = await mountAt(AttackProtection, '/t/acme/attack-protection', () => ({ status: 200, body: captcha }))
    await tab(wrapper, 'CAPTCHA')
    await wrapper.get('#active_provider_id').setValue('recaptcha_v2')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.at(-1)?.body).toEqual({ active_provider_id: 'recaptcha_v2' })
    await wrapper.get('#hcaptcha-secret').setValue('sensitive-credential-123')
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(calls.at(-1)?.body).toEqual({ hcaptcha: { site_key: 'site', secret: 'sensitive-credential-123' } })
    expect((wrapper.get('#hcaptcha-secret').element as HTMLInputElement).value).toBe('')
    expect(wrapper.html()).not.toContain('sensitive-credential-123')
    wrapper.unmount()
  })
})

it('refuses incomplete replacement provider credentials with a field error', async () => {
  const { wrapper, calls } = await mountAt(AttackProtection, '/t/acme/attack-protection', () => ({ status: 200, body: { active_provider_id: 'hcaptcha', hcaptcha: { site_key: 'old-site' } } }))
  await tab(wrapper, 'CAPTCHA')
  await wrapper.get('#hcaptcha-site_key').setValue('new-site')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(0)
  expect(wrapper.get('#hcaptcha-secret-error').text()).toContain('complete')
  wrapper.unmount()
})

it('offers hosted locale codes independently from the console language', async () => {
  const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', () => ({ status: 200, body: { ...settings, enabled_locales: ['en'] } }))
  await tab(wrapper, 'Languages')
  await wrapper.get('#hosted-locale').setValue('fr')
  await wrapper.findAll('button').find(b => b.text() === 'Add hosted language')!.trigger('click')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ enabled_locales: ['en', 'fr'] })
  wrapper.unmount()
})

it.each([
  ['Suspicious IP', 'stage-pre-login-rate', '34560', 'suspicious-ip-throttling', { stage: { 'pre-login': { rate: 34560 } } }],
  ['Breached passwords', 'stage-pre-change-password-shields', 'block', 'breached-password-detection', { stage: { 'pre-change-password': { shields: ['block'] } } }],
  ['Bot detection', 'challenge_password_policy', 'always', 'bot-detection', { challenge_password_policy: 'always' }],
] as const)('saves only the edited %s policy', async (name, id, value, endpoint, expected) => {
  const { wrapper, calls } = await mountAt(AttackProtection, '/t/acme/attack-protection', () => ({ status: 200, body: { enabled: false, stage: { 'pre-login': { rate: 864000, max_attempts: 100 }, 'pre-change-password': { shields: [] } }, challenge_password_policy: 'never' } }))
  await tab(wrapper, name)
  await wrapper.get('#' + id).setValue(value)
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.at(-1)?.url).toContain('/attack-protection/' + endpoint)
  expect(calls.at(-1)?.body).toEqual(expected)
  expect(calls.every(c => new URL(c.url).host === 'acme.example.test')).toBe(true)
  wrapper.unmount()
})

it('ignores a delayed settings load after switching tenants', async () => {
  let finish!: (r: Reply) => void
  const { wrapper, router } = await mountAt(Settings, '/t/acme/settings', c => c.url.includes('acme.example.test') ? new Promise(r => { finish = r }) : { status: 200, body: { ...settings, friendly_name: 'New tenant' } })
  expect(wrapper.text()).toContain('Loading')
  await router.push('/t/system/settings'); await flushPromises()
  finish({ status: 200, body: settings }); await flushPromises()
  expect((wrapper.get('#friendly_name').element as HTMLInputElement).value).toBe('New tenant')
  wrapper.unmount()
})

it('discards unsaved edits on tenant switch before saving', async () => {
  const { wrapper, router, calls } = await mountAt(Settings, '/t/acme/settings', () => ({ status: 200, body: settings }))
  await wrapper.get('#friendly_name').setValue('Old tenant draft')
  await router.push('/t/system/settings'); await flushPromises()
  await wrapper.get('#support_url').setValue('https://support.example.test/')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ support_url: 'https://support.example.test/' })
  expect(calls.at(-1)?.url).toContain('system.example.test')
  wrapper.unmount()
})

it('associates and focuses a server validation error on a toggle', async () => {
  const { wrapper } = await mountAt(AttackProtection, '/t/acme/attack-protection', c => c.method === 'PATCH' ? apiError(400, 'invalid_body', 'enabled: invalid setting') : { status: 200, body: { enabled: false } })
  await wrapper.get('[role=switch]').trigger('click')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  const control = wrapper.get('[role=switch]')
  expect(control.attributes('id')).toBe('enabled')
  expect(control.attributes('aria-invalid')).toBe('true')
  expect(control.attributes('aria-describedby')).toContain('enabled-error')
  expect(wrapper.get('#enabled-error').text()).toContain('invalid setting')
  expect(document.activeElement).toBe(control.element)
  wrapper.unmount()
})

it('preserves and exposes optional Arkose fields in a full provider replacement', async () => {
  const arkose = { site_key: 'saved-site', client_subdomain: 'client', verify_subdomain: 'verify', fail_open: true }
  const { wrapper, calls } = await mountAt(AttackProtection, '/t/acme/attack-protection', () => ({ status: 200, body: { active_provider_id: 'arkose', arkose } }))
  await tab(wrapper, 'CAPTCHA')
  await wrapper.get('#arkose-secret').setValue('new-credential')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ arkose: { ...arkose, secret: 'new-credential' } })
  expect((wrapper.get('#arkose-client_subdomain').element as HTMLInputElement).value).toBe('client')
  expect((wrapper.get('#arkose-verify_subdomain').element as HTMLInputElement).value).toBe('verify')
  await wrapper.get('#arkose-fail_open').trigger('click')
  await wrapper.get('#arkose-client_subdomain').setValue('')
  await wrapper.get('#arkose-secret').setValue('second-credential')
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ arkose: { ...arkose, client_subdomain: '', fail_open: false, secret: 'second-credential' } })
  wrapper.unmount()
})
