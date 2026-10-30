import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { confirmPrompt, mountAt } from '../../test/mount'
import Settings from './TenantSettings.vue'

afterEach(() => { document.body.innerHTML = '' })

describe('custom signing keys settings', () => {
  it('keeps the stored-only warning visible and rejects private-key material before writing', async () => {
    const { wrapper, calls } = await mountAt(Settings, '/t/acme/settings', c => ({ status: 200, body: c.method === 'GET' ? { keys: [] } : { keys: [] } }))
    await wrapper.findAll('[role=tab]').find(x => x.text().includes('Custom signing'))!.trigger('mousedown')
    await flushPromises()
    expect(wrapper.text()).toContain('stored only')
    await wrapper.get('textarea').setValue('{"keys":[{"kty":"RSA","kid":"private","n":"abc","e":"AQAB","d":"secret"}]}')
    await wrapper.findAll('button').find(x => x.text().includes('Replace'))!.trigger('click')
    await flushPromises()
    expect(calls.filter(c => c.method === 'PUT')).toHaveLength(0)
    expect(wrapper.text()).toContain('Private key material')
    wrapper.unmount()
    vi.unstubAllGlobals()
  })
})

import CustomSigningKeys from './CustomSigningKeys.vue'
import { deferred, signingMount } from './signing-test'
import { tenant, type Reply } from '../../test/services'

it('ignores a completed replacement after switching tenants and preserves the new tenant editor', async () => {
  const oldWrite = deferred<Reply>()
  const { wrapper } = signingMount(CustomSigningKeys, c => c.method === 'PUT' ? oldWrite.promise : { status: 200, body: { keys: [] } })
  await flushPromises()
  await wrapper.get('textarea').setValue('{"keys":[{"kid":"old","kty":"RSA","n":"abc","e":"AQAB"}]}')
  await wrapper.findAll('button').find(b => b.text().includes('Replace'))!.trigger('click'); await flushPromises()
  await confirmPrompt()
  await wrapper.setProps({ tenant: tenant('other') }); await flushPromises()
  await wrapper.get('textarea').setValue('{"keys":[{"kid":"new-edit"}]}')
  oldWrite.resolve({ status: 200, body: { keys: [{ kid: 'old' }] } }); await flushPromises()
  expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toContain('new-edit')
  wrapper.unmount(); vi.unstubAllGlobals()
})

it('keeps input and announces validation and permission errors without changing the stored set', async () => {
  const { wrapper, calls } = signingMount(CustomSigningKeys, c => ({ status: c.method === 'GET' ? 200 : 403, body: c.method === 'GET' ? { keys: [] } : { message: 'Permission denied' } }))
  await flushPromises()
  const input = '{"keys":[{"kid":"keep","kty":"RSA","n":"abc","e":"AQAB"}]}'
  await wrapper.get('textarea').setValue(input)
  await wrapper.findAll('button').find(b => b.text().includes('Replace'))!.trigger('click'); await flushPromises()
  await confirmPrompt()
  expect(wrapper.get('[role=alert]').text()).toContain('Permission denied')
  expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe(input)
  expect(calls.filter(c => c.method === 'PUT')).toHaveLength(1)
  expect(wrapper.text()).toContain('stored only')
  wrapper.unmount(); vi.unstubAllGlobals()
})

it('locks the editor and mutations until the initial tenant read completes', async () => {
  const initial = deferred<Reply>()
  const { wrapper, calls } = signingMount(CustomSigningKeys, () => initial.promise)
  expect((wrapper.get('textarea').element as HTMLTextAreaElement).disabled).toBe(true)
  expect(wrapper.findAll('button').every(b => (b.element as HTMLButtonElement).disabled)).toBe(true)
  initial.resolve({ status: 200, body: { keys: [{ kid: 'stored' }] } }); await flushPromises()
  expect((wrapper.get('textarea').element as HTMLTextAreaElement).disabled).toBe(false)
  expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toContain('stored')
  expect(calls.every(c => c.method === 'GET')).toBe(true)
  wrapper.unmount()
})

it('bounds a custom JWKS before sending it and keeps the input on rejection', async () => {
  const { wrapper, calls } = signingMount(CustomSigningKeys, () => ({ status: 200, body: { keys: [] } }))
  await flushPromises()
  const input = JSON.stringify({ keys: [{ kid: 'huge', kty: 'RSA', n: 'a'.repeat(66_000), e: 'AQAB' }] })
  await wrapper.get('textarea').setValue(input)
  await wrapper.findAll('button').find(b => b.text().includes('Replace'))!.trigger('click'); await flushPromises()
  expect(calls.filter(c => c.method === 'PUT')).toHaveLength(0)
  expect(wrapper.get('[role=alert]').text()).toContain('64')
  expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe(input)
  wrapper.unmount(); vi.unstubAllGlobals()
})
