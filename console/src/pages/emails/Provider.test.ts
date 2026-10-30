import { flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import { apiError, confirmPrompt, mountAt } from '../../test/mount'
import Provider from './Provider.vue'

const stored = { name: 'sendgrid', enabled: false, default_from_address: 'mail@example.test', settings: {} }

describe('Email provider settings', () => {
  it('keeps secret inputs empty and omits blank credentials when saving', async () => {
    const { wrapper, calls } = await mountAt(Provider, '/t/acme/emails', (c) => {
      if (c.method === 'GET') return { status: 200, body: { ...stored, credentials: { api_key: 'sentinel-secret' } } }
      if (c.method === 'PATCH') return { status: 200, body: stored }
      throw new Error(`${c.method} ${c.url}`)
    })
    const secret = wrapper.find('input[type="password"]')
    expect((secret.element as HTMLInputElement).value).toBe('')
    expect(wrapper.text()).not.toContain('sentinel-secret')
    await wrapper.find('input[type="checkbox"]').setValue(true)
    await wrapper.find('button').trigger('click')
    await flushPromises()
    const save = calls.find((c) => c.method === 'PATCH')!
    expect(save.body).not.toHaveProperty('credentials')
    expect(wrapper.text()).toContain('Changes saved.')
    wrapper.unmount()
  })

  it('locks editing after a failed read and lets the operator retry', async () => {
    let failed = true
    const { wrapper, calls } = await mountAt(Provider, '/t/acme/emails', () => {
      if (failed) return apiError(500, 'internal_error', 'Internal error')
      return { status: 200, body: stored }
    })
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
    expect(wrapper.find('#email-provider-name').exists()).toBe(false)
    failed = false
    await wrapper.find('button').trigger('click')
    await flushPromises()
    expect(wrapper.find('#email-provider-name').exists()).toBe(true)
    expect(calls.filter((c) => c.method === 'GET')).toHaveLength(2)
    wrapper.unmount()
  })

  it('confirms deletion and returns to server fallback state', async () => {
    const { wrapper, calls } = await mountAt(Provider, '/t/acme/emails', (c) => {
      if (c.method === 'GET') return { status: 200, body: stored }
      if (c.method === 'DELETE') return { status: 204 }
      throw new Error(c.method)
    })
    await wrapper.findAll('button').find((b) => b.text() === 'Delete provider')!.trigger('click')
    await flushPromises()
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    await confirmPrompt()
    expect(calls.some((c) => c.method === 'DELETE')).toBe(true)
    expect(wrapper.text()).toContain('No tenant provider is configured')
    vi.unstubAllGlobals()
    wrapper.unmount()
  })

  it('refreshes after a lost write response without discarding the draft or retrying', async () => {
    const { wrapper, calls } = await mountAt(Provider, '/t/acme/emails', (c) => {
      if (c.method === 'GET') return { status: 200, body: stored }
      if (c.method === 'PATCH') return apiError(500, 'internal_error', 'Internal error')
      throw new Error(`${c.method} ${c.url}`)
    })
    await wrapper.find('#email-default-from').setValue('draft@example.test')
    await wrapper.findAll('button').find((b) => b.text() === 'Save provider')!.trigger('click')
    await flushPromises()
    expect(calls.filter((c) => c.method === 'PATCH')).toHaveLength(1)
    expect(calls.filter((c) => c.method === 'GET')).toHaveLength(2)
    expect((wrapper.find('#email-default-from').element as HTMLInputElement).value).toBe('draft@example.test')
    expect(wrapper.find('[role="alert"]').text()).toContain('response was lost')
    wrapper.unmount()
  })
})

it('allows enabling custom delivery and explains its required Action binding', async () => {
 const { wrapper, calls } = await mountAt(Provider, '/t/acme/emails', c => ({ status: 200, body: c.method === 'PATCH' ? { ...stored, name: 'custom', enabled: true } : stored }))
 await wrapper.get('#email-provider-name').setValue('custom')
 expect(wrapper.get('option[value=custom]').text()).toBe('Custom')
 expect(wrapper.text()).toContain('custom-email-provider')
 const enabled = wrapper.get('input[type=checkbox]'); expect(enabled.attributes('disabled')).toBeUndefined(); await enabled.setValue(true)
 await wrapper.findAll('button').find(b => b.text() === 'Save provider')!.trigger('click'); await flushPromises()
 expect(calls.find(c => c.method === 'PATCH')!.body).toMatchObject({ name: 'custom', enabled: true }); wrapper.unmount()
})
