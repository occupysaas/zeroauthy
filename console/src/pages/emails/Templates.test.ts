import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import type { Reply } from '../../test/services'
import { mountAt } from '../../test/mount'
import Templates from './Templates.vue'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => { resolve = r })
  return { promise, resolve }
}

describe('Email templates', () => {
  it('ignores a stale template response when selection changes', async () => {
    const first = deferred<Reply>()
    const { wrapper } = await mountAt(Templates, '/t/acme/emails', (c) => {
      if (c.url.endsWith('/verify_email')) return first.promise
      if (c.url.endsWith('/reset_email')) return { status: 200, body: { template: 'reset_email', enabled: true, subject: 'Reset subject', body: 'Reset body' } }
      throw new Error(c.url)
    })
    await wrapper.find('#email-template-select').setValue('reset_email')
    await flushPromises()
    expect((wrapper.find('#email-template-body').element as HTMLTextAreaElement).value).toBe('Reset body')
    first.resolve({ status: 200, body: { template: 'verify_email', enabled: true, subject: 'Verify subject', body: 'Stale verify body' } })
    await flushPromises()
    expect((wrapper.find('#email-template-body').element as HTMLTextAreaElement).value).toBe('Reset body')
    wrapper.unmount()
  })

  it('ignores a stale response when the active tenant changes', async () => {
    const acme = deferred<Reply>()
    const { wrapper, router } = await mountAt(Templates, '/t/acme/emails', (c) => {
      if (c.url.includes('acme.example.test')) return acme.promise
      if (c.url.includes('system.example.test')) return { status: 200, body: { template: 'verify_email', enabled: true, subject: 'System subject', body: 'System body' } }
      throw new Error(c.url)
    })
    await router.push('/t/system/emails')
    await flushPromises()
    expect((wrapper.find('#email-template-body').element as HTMLTextAreaElement).value).toBe('System body')
    acme.resolve({ status: 200, body: { template: 'verify_email', enabled: true, subject: 'Acme subject', body: 'Stale acme body' } })
    await flushPromises()
    expect((wrapper.find('#email-template-body').element as HTMLTextAreaElement).value).toBe('System body')
    wrapper.unmount()
  })

  it('labels missing templates as not configured and preserves edits after write errors', async () => {
    const { wrapper, calls } = await mountAt(Templates, '/t/acme/emails', (c) => {
      if (c.method === 'GET') return { status: 404, body: { statusCode: 404, error: 'Not Found', errorCode: 'inexistent_email_template', message: 'missing' } }
      return { status: 400, body: { statusCode: 400, error: 'Bad Request', errorCode: 'invalid_body', message: 'failed' } }
    })
    expect(wrapper.text()).toContain('Not configured')
    await wrapper.find('#email-template-subject').setValue('Draft subject')
    await wrapper.find('#email-template-body').setValue('Draft body')
    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect(calls.at(-1)?.method).toBe('POST')
    expect((wrapper.find('#email-template-body').element as HTMLTextAreaElement).value).toBe('Draft body')
    expect((wrapper.find('#email-template-subject').element as HTMLInputElement).value).toBe('Draft subject')
    expect(wrapper.find('[role="alert"]').text()).toContain('failed')
    wrapper.unmount()
  })

  it('refreshes after an uncertain write and keeps the unsaved draft without retrying', async () => {
    const { wrapper, calls } = await mountAt(Templates, '/t/acme/emails', (c) => {
      if (c.method === 'GET' && c.url.endsWith('/verify_email')) return { status: 404, body: { statusCode: 404, error: 'Not Found', errorCode: 'inexistent_email_template', message: 'missing' } }
      if (c.method === 'POST') return { status: 500, body: { statusCode: 500, error: 'Internal Server Error', errorCode: 'internal_error', message: 'Internal error' } }
      if (c.method === 'GET') return { status: 200, body: { template: 'verify_email', enabled: true, subject: 'Remote subject', body: 'Remote body' } }
      throw new Error(`${c.method} ${c.url}`)
    })
    await wrapper.find('#email-template-subject').setValue('Draft subject')
    await wrapper.find('#email-template-body').setValue('Draft body')
    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(1)
    expect(calls.filter((c) => c.method === 'GET')).toHaveLength(2)
    expect((wrapper.find('#email-template-body').element as HTMLTextAreaElement).value).toBe('Draft body')
    expect((wrapper.find('#email-template-subject').element as HTMLInputElement).value).toBe('Draft subject')
    expect(wrapper.find('[role="alert"]').text()).toContain('response was lost')
    wrapper.unmount()
  })
})
