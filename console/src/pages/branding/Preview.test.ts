import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import Preview from './Preview.vue'

describe('Universal Login preview', () => {
  it('offers every hosted screen and confines authored HTML to a capability-free frame', async () => {
    const { wrapper, calls } = await mountAt(Preview, '/t/acme/branding', () => ({ status: 200, body: { html: '<html><head></head><body><h1>Authored preview</h1></body></html>', warnings: ['Assets blocked'] } }))
    expect(wrapper.findAll('#branding-preview-screen option')).toHaveLength(17)
    await wrapper.find('button').trigger('click'); await flushPromises()
    expect(calls[0]?.url).toBe('https://admin.example.test/api/system/tenants/acme/branding/preview')
    expect(calls[0]?.body).toEqual({ screen: 'login', language: 'en' })
    const frame = wrapper.find('iframe')
    expect(frame.attributes('sandbox')).toBe('')
    expect(frame.attributes('srcdoc')).toContain('Authored preview')
    expect(wrapper.find('h1').exists()).toBe(false)
    expect(wrapper.text()).toContain('Assets blocked')
    wrapper.unmount()
  })

  it('discards a late response when the selected screen changes', async () => {
    let resolve!: (r: { status: number; body: unknown }) => void
    const { wrapper } = await mountAt(Preview, '/t/acme/branding', () => new Promise(r => { resolve = r }))
    await wrapper.find('button').trigger('click'); await flushPromises()
    await wrapper.find('select').setValue('signup')
    resolve({ status: 200, body: { html: '<p>Old login</p>', warnings: [] } }); await flushPromises()
    expect(wrapper.find('iframe').exists()).toBe(false)
    wrapper.unmount()
  })

  it('shows failed preview visibly and does not retain an earlier document', async () => {
    let attempts = 0
    const { wrapper } = await mountAt(Preview, '/t/acme/branding', () => ++attempts === 1 ? { status: 200, body: { html: '<p>Old</p>', warnings: [] } } : { status: 400, body: { message: 'Invalid template' } })
    await wrapper.find('button').trigger('click'); await flushPromises()
    expect(wrapper.find('iframe').exists()).toBe(true)
    await wrapper.find('button').trigger('click'); await flushPromises()
    expect(wrapper.find('iframe').exists()).toBe(false)
    expect(wrapper.text()).toContain('Invalid template')
    wrapper.unmount()
  })
})

it('binds validated preview styles to the inherited console CSP nonce', async () => {
 const parent = '0123456789012345678901'
 const child = 'abcdefghijklmnopqrstuv'
 const meta = document.createElement('meta'); meta.name = 'zeroauthy-preview-style-nonce'; meta.content = parent; document.head.append(meta)
 const { wrapper } = await mountAt(Preview, '/t/acme/branding', () => ({ status: 200, body: { html: `<html><head><meta http-equiv="Content-Security-Policy" content="style-src 'nonce-${child}'"><style nonce="${child}">body {display:grid}</style></head><body>Example</body></html>`, warnings: [] } }))
 await wrapper.find('button').trigger('click'); await flushPromises()
 const doc = wrapper.find('iframe').attributes('srcdoc')
 expect(doc).toContain(`style-src 'nonce-${parent}'`)
 expect(doc).toContain(`<style nonce="${parent}">`)
 expect(doc).not.toContain(child)
 wrapper.unmount(); meta.remove()
})
