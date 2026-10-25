import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import Preview from './Preview.vue'

describe('Email preview and test', () => {
  it('offers every supported saved template for preview and test', async () => {
    const { wrapper } = await mountAt(Preview, '/t/acme/emails', (c) => {
      if (c.method === 'GET' && c.url.includes('/email-templates/')) return { status: 404, body: {} }
      throw new Error(`${c.method} ${c.url}`)
    })
    const options = wrapper.findAll('#email-preview-template option').map((option) => (option.element as HTMLOptionElement).value)
    expect(options).toEqual(['verify_email', 'verify_email_by_code', 'auth_email_by_code', 'reset_email', 'reset_email_by_code', 'welcome_email', 'blocked_account', 'stolen_credentials', 'enrollment_email', 'mfa_oob_code', 'user_invitation', 'async_approval', 'change_password', 'password_reset'])
    wrapper.unmount()
  })

  it('previews unsaved edits in an isolated frame and tests only the saved template once', async () => {
    const { wrapper, calls } = await mountAt(Preview, '/t/acme/emails', (c) => {
      if (c.method === 'GET' && c.url.includes('/email-templates/')) return { status: 200, body: { template: 'verify_email', enabled: true, subject: 'Saved subject', body: 'Saved body' } }
      if (c.method === 'POST' && c.url.endsWith('/emails/preview')) return { status: 200, body: { from: 'mail@example.test', subject: 'Rendered', text: '', html: '<h1>Preview body</h1><script>bad()</script><img src="https://remote.example.test/image.png">', resultUrl: 'https://example.invalid/verify_email' } }
      if (c.method === 'POST' && c.url.endsWith('/emails/test')) throw new TypeError('Failed to fetch')
      throw new Error(`${c.method} ${c.url}`)
    })
    await wrapper.find('#email-preview-body').setValue('Unsaved body')
    await wrapper.findAll('button').find((b) => b.text() === 'Render preview')!.trigger('click')
    await flushPromises()
    const previewCall = calls.find((c) => c.url.endsWith('/emails/preview'))!
    expect(previewCall.body).toEqual({ template: 'verify_email', overrides: { body: 'Unsaved body' } })
    const frame = wrapper.find('iframe')
    expect(frame.attributes('sandbox')).toBe('')
    expect(frame.attributes('srcdoc')).toContain("default-src 'none'")
    expect(frame.attributes('srcdoc')).not.toContain('allow-scripts')
    expect(frame.attributes('srcdoc')).not.toContain('allow-same-origin')
    expect(frame.attributes('srcdoc')).not.toContain('allow-forms')
    expect(frame.attributes('srcdoc')).toContain('https://remote.example.test/image.png')
    expect(frame.attributes('srcdoc')).toContain('<script>bad()</script>')
    expect(wrapper.find('script').exists()).toBe(false)

    await wrapper.findAll('button').find((b) => b.text() === 'Send test of saved template')!.trigger('click')
    await flushPromises()
    const testCalls = calls.filter((c) => c.url.endsWith('/emails/test'))
    expect(testCalls).toHaveLength(1)
    expect(testCalls[0]!.body).toEqual({ template: 'verify_email' })
    expect(wrapper.text()).toContain('The request failed after it started')
    expect((wrapper.find('#email-preview-body').element as HTMLTextAreaElement).value).toBe('Unsaved body')
    wrapper.unmount()
  })
})
