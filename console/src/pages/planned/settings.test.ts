import { describe, expect, it } from 'vitest'
import { plannedPages } from './index'
import { assertPreviewInert } from './preview'
import { mountAt } from '../../test/mount'

const never = () => ({ status: 500, body: {} })

async function open(key: string) {
  return mountAt(plannedPages[key]!, `/t/acme/${key}`, never)
}

describe('settings-style planned previews', () => {
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

})
