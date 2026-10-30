import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { confirmPrompt, mountAt } from '../../test/mount'
import Settings from './TenantSettings.vue'

afterEach(() => { document.body.innerHTML = '' })

describe('managed signing keys settings', () => {
  it('loads metadata and requires confirmation before rotating once', async () => {
    const keys = [{ kid: 'current-kid', alg: 'RS256', cert: 'pem-data', current: true, next: false, previous: false, revoked: false }]
    const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', c => {
      if (c.url.endsWith('/api/v2/keys/signing')) return { status: 200, body: keys }
      if (c.method === 'POST' && c.url.endsWith('/api/v2/keys/signing/rotate')) return { status: 201, body: keys[0] }
      return { status: 200, body: { keys: [] } }
    })
    await wrapper.findAll('[role=tab]').find(x => x.text().includes('Signing keys'))!.trigger('mousedown')
    await flushPromises()
    expect(wrapper.text()).toContain('current-kid')
    await wrapper.findAll('button').find(x => x.text().includes('Rotate'))!.trigger('click')
    await flushPromises()
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
    await confirmPrompt()
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(1)
    expect(calls.find(c => c.method === 'POST')?.url).toContain('/api/v2/keys/signing/rotate')
    wrapper.unmount()
    vi.unstubAllGlobals()
  })

  it('blocks another rotation after a lost response until a later refresh succeeds', async () => {
    let lists = 0
    const keys = [{ kid: 'previous-kid', alg: 'RS256', current: false, next: false, previous: true, revoked: false }]
    const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', c => {
      if (c.url.endsWith('/api/v2/keys/signing')) {
        lists++
        return lists === 2 ? { status: 503, body: { message: 'refresh unavailable' } } : { status: 200, body: keys }
      }
      if (c.method === 'POST') return { status: 503, body: { message: 'response lost' } }
      return { status: 200, body: keys[0] }
    })
    await wrapper.findAll('[role=tab]').find(x => x.text().includes('Signing keys'))!.trigger('mousedown')
    await flushPromises()
    const rotate = wrapper.findAll('button').find(x => x.text().includes('Rotate'))!
    await rotate.trigger('click'); await flushPromises()
    await confirmPrompt()
    expect(wrapper.text()).toContain('Refresh the key list')
    expect((rotate.element as HTMLButtonElement).disabled).toBe(true)
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(1)
    await wrapper.findAll('button').find(x => x.text().includes('Refresh'))!.trigger('click'); await flushPromises()
    expect((rotate.element as HTMLButtonElement).disabled).toBe(false)
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(1)
    wrapper.unmount()
    vi.unstubAllGlobals()
  })

  it('does not allow key changes for the reserved tenant', async () => {
    const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', () => ({ status: 200, body: [] }), { reserved: true })
    await wrapper.findAll('[role=tab]').find(x => x.text().includes('Signing keys'))!.trigger('mousedown')
    await flushPromises()
    expect((wrapper.findAll('button').find(x => x.text().includes('Rotate'))!.element as HTMLButtonElement).disabled).toBe(true)
    expect(calls.some(c => c.method === 'POST' || c.method === 'PUT')).toBe(false)
    wrapper.unmount()
  })
})

import SigningKeys from './SigningKeys.vue'
import { deferred, signingMount } from './signing-test'
import { tenant, type Reply } from '../../test/services'

it('does not apply old fetches or mutation errors to another tenant', async () => {
  const oldWrite = deferred<Reply>()
  const { wrapper, calls } = signingMount(SigningKeys, c => c.method === 'POST' ? oldWrite.promise : { status: 200, body: [{ kid: c.url.includes('other') ? 'other-current' : 'old-current', current: true, alg: 'RS256' }] })
  await flushPromises()
  await wrapper.findAll('button').find(b => b.text().includes('Rotate'))!.trigger('click'); await flushPromises()
  await confirmPrompt()
  await wrapper.setProps({ tenant: tenant('other') }); await flushPromises()
  oldWrite.resolve({ status: 503, body: { message: 'old tenant timeout' } }); await flushPromises()
  expect(wrapper.text()).toContain('other-current')
  expect(wrapper.text()).not.toContain('old tenant timeout')
  expect((wrapper.findAll('button').find(b => b.text().includes('Rotate'))!.element as HTMLButtonElement).disabled).toBe(false)
  expect(calls.filter(c => c.method === 'POST')).toHaveLength(1)
  wrapper.unmount(); vi.unstubAllGlobals()
})

it('disables stale revocation during refresh and offers public certificate copy and download', async () => {
  const delayed = deferred<Reply>()
  let lists = 0
  const { wrapper, calls } = signingMount(SigningKeys, () => ++lists === 1 ? { status: 200, body: [{ kid: 'previous', alg: 'RS256', previous: true, cert: 'PUBLIC PEM' }] } : delayed.promise)
  await flushPromises()
  const revoke = wrapper.findAll('button').find(b => b.text().includes('Revoke'))!
  await wrapper.findAll('button').find(b => b.text().includes('Refresh'))!.trigger('click')
  expect((revoke.element as HTMLButtonElement).disabled).toBe(true)
  expect(wrapper.findAll('button').some(b => b.text().includes('Copy'))).toBe(true)
  expect(wrapper.findAll('button').some(b => b.text().includes('Download'))).toBe(true)
  delayed.resolve({ status: 200, body: [{ kid: 'previous', alg: 'RS256', revoked: true }] }); await flushPromises()
  expect(wrapper.findAll('button').some(b => b.text().includes('Revoke previous'))).toBe(false)
  expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
  wrapper.unmount(); vi.unstubAllGlobals()
})

it('announces a denied mutation and preserves focus without retrying it', async () => {
  const { wrapper, calls } = signingMount(SigningKeys, c => c.method === 'POST' ? { status: 403, body: { message: 'Read-only delegation' } } : { status: 200, body: [{ kid: 'current', current: true, alg: 'RS256' }] })
  await flushPromises()
  const rotate = wrapper.findAll('button').find(b => b.text().includes('Rotate'))!
  ;(rotate.element as HTMLButtonElement).focus()
  await rotate.trigger('click'); await flushPromises()
  await confirmPrompt()
  expect(wrapper.get('[role=alert]').text()).toContain('Read-only delegation')
  expect(document.activeElement).toBe(rotate.element)
  expect(calls.filter(c => c.method === 'POST')).toHaveLength(1)
  wrapper.unmount(); vi.unstubAllGlobals()
})

it('copies and downloads only the displayed public certificate', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined)
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  const create = vi.fn((blob: Blob) => { expect(blob).toBeInstanceOf(Blob); return 'blob:public-cert' }), revoke = vi.fn()
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke }))
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
  const { wrapper, calls } = signingMount(SigningKeys, () => ({ status: 200, body: [{ kid: 'public', current: true, alg: 'RS256', cert: 'PUBLIC CERTIFICATE' }] }))
  await flushPromises()
  await wrapper.findAll('button').find(b => b.text().includes('Copy'))!.trigger('click'); await flushPromises()
  expect(writeText).toHaveBeenCalledWith('PUBLIC CERTIFICATE')
  await wrapper.findAll('button').find(b => b.text().includes('Download'))!.trigger('click')
  expect(click).toHaveBeenCalledOnce()
  expect(create.mock.calls[0]?.[0]).toBeInstanceOf(Blob)
  expect(revoke).toHaveBeenCalledWith('blob:public-cert')
  expect(calls.every(c => c.method === 'GET')).toBe(true)
  expect(wrapper.text()).not.toContain('1970')
  wrapper.unmount(); click.mockRestore(); vi.unstubAllGlobals()
})

it('ignores an old tenant fetch that completes after the current fetch', async () => {
  const old = deferred<Reply>()
  const { wrapper } = signingMount(SigningKeys, c => c.url.includes('acme') ? old.promise : { status: 200, body: [{ kid: 'new-tenant', current: true, alg: 'RS256' }] })
  await wrapper.setProps({ tenant: tenant('other') }); await flushPromises()
  old.resolve({ status: 200, body: [{ kid: 'stale-tenant', current: true, alg: 'RS256' }] }); await flushPromises()
  expect(wrapper.text()).toContain('new-tenant'); expect(wrapper.text()).not.toContain('stale-tenant')
  wrapper.unmount()
})

it('shows available lifecycle times and certificate details without inventing dates', async () => {
  const { wrapper } = signingMount(SigningKeys, () => ({ status: 200, body: [{ kid: 'retired', alg: 'RS256', revoked: true, current_until: '2026-10-25T12:00:00Z', revoked_at: '2026-10-25T13:00:00Z', fingerprint: 'fingerprint-value', thumbprint: 'thumbprint-value' }] }))
  await flushPromises()
  expect(wrapper.text()).toContain('2026-10-25T12:00:00Z')
  expect(wrapper.text()).toContain('2026-10-25T13:00:00Z')
  expect(wrapper.text()).toContain('fingerprint-value')
  expect(wrapper.text()).toContain('thumbprint-value')
  expect(wrapper.text()).not.toContain('1970')
  wrapper.unmount()
})
