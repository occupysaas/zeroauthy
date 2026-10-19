import { describe, expect, it } from 'vitest'
import { plannedPages } from './index'
import { assertPreviewInert } from './preview'
import { mountAt } from '../../test/mount'

const never = () => ({ status: 500, body: {} })

async function open(key: string) {
  return mountAt(plannedPages[key]!, `/t/acme/${key}`, never)
}

describe('settings-style planned previews', () => {
  it('attack protection has three panels', async () => {
    const { wrapper, calls } = await open('attack-protection')
    expect(wrapper.get('h1').text()).toBe('Attack protection')
    expect(wrapper.findAll('h2').map((h) => h.text())).toEqual(['Brute-force protection', 'Breached password detection', 'Suspicious IP throttling'])
    assertPreviewInert(wrapper)
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })

  it('multi-factor lists factors and policy', async () => {
    const { wrapper, calls } = await open('mfa')
    expect(wrapper.get('h1').text()).toBe('Multi-factor')
    const text = wrapper.text()
    for (const f of ['One-time password', 'Push notification', 'SMS', 'Voice', 'Email', 'WebAuthn with security keys', 'WebAuthn with device biometrics', 'Recovery code']) {
      expect(text).toContain(f)
    }
    expect(wrapper.findAll('[role=switch]')).toHaveLength(8)
    expect(wrapper.findAll('fieldset label').map((l) => l.text())).toEqual(['Never', 'Always', 'Adaptive'])
    assertPreviewInert(wrapper)
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })

  it('tenant settings tabs switch the panel', async () => {
    const { wrapper, calls } = await open('settings')
    expect(wrapper.get('h1').text()).toBe('Tenant settings')
    const tabs = () => wrapper.findAll('[role=tab]')
    expect(tabs().map((x) => x.text())).toEqual(['General', 'Session', 'Languages', 'Login'])
    expect(wrapper.text()).toContain('Friendly name')
    for (const [name, field] of [['Session', 'Inactivity timeout'], ['Languages', 'Default language'], ['Login', 'Default login route'], ['General', 'Friendly name']] as const) {
      await tabs().find((x) => x.text() === name)!.trigger('mousedown')
      expect(wrapper.text()).toContain(field)
      if (name === 'Session') expect(wrapper.text()).not.toContain('Friendly name')
      assertPreviewInert(wrapper)
    }
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })

  it('branding shows four fields and disabled colors', async () => {
    const { wrapper, calls } = await open('branding')
    expect(wrapper.get('h1').text()).toBe('Universal Login')
    const labels = wrapper.findAll('label').map((l) => l.text())
    for (const l of ['Logo URL', 'Favicon URL', 'Primary color', 'Page background color']) expect(labels).toContain(l)
    const primary = wrapper.get('input#br-primary')
    const bg = wrapper.get('input#br-bg')
    expect(primary.attributes('disabled')).toBeDefined()
    expect(bg.attributes('disabled')).toBeDefined()
    expect((primary.element as HTMLInputElement).value).toBe('#d7141a')
    expect((bg.element as HTMLInputElement).value).toBe('#ffffff')
    assertPreviewInert(wrapper)
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })

  it('email templates picker switches the panel heading', async () => {
    const { wrapper, calls } = await open('emails')
    expect(wrapper.get('h1').text()).toBe('Email templates')
    const radios = () => wrapper.findAll('[data-preview-nav] button[aria-pressed]')
    expect(radios().map((r) => r.text())).toEqual(['Verify email', 'Welcome', 'Change password', 'Blocked account', 'Password breach', 'MFA enrollment', 'User invitation'])
    expect(wrapper.get('h2').text()).toBe('Verify email')
    expect(radios()[0]!.attributes('aria-pressed')).toBe('true')
    await radios()[1]!.trigger('click')
    expect(wrapper.get('h2').text()).toBe('Welcome')
    expect(radios()[1]!.attributes('aria-pressed')).toBe('true')
    expect(radios()[0]!.attributes('aria-pressed')).toBe('false')
    expect(wrapper.get('textarea').attributes('disabled')).toBeDefined()
    assertPreviewInert(wrapper)
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })
})
