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

})
