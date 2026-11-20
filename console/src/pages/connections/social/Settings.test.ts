import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { connection } from '../../../test/services'
import Detail from './Detail.vue'
import { appleKey } from '../../../test/apple'
import { githubOptions } from '../../../test/github'

const clientId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
describe('Microsoft settings', () => {
  it.each(['windowslive', 'waad'])('keeps %s identity bindings read-only and omits unchanged secret', async strategy => {
    const options = { client_id: clientId, ...(strategy === 'waad' ? { tenant_domain: 'acme.onmicrosoft.com', useCommonEndpoint: false, domain: 'Display only' } : { strategy_version: 2 }) }
    const item = connection('con_ms', { strategy, options })
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/enterprise/con_ms', () => ({ status: 200, body: item }), { domains: ['login.acme.com', 'other.acme.com'] })
    expect(wrapper.find<HTMLInputElement>('#social-client-id').element.readOnly).toBe(true)
    expect(wrapper.find('#social-script').exists()).toBe(false)
    expect(wrapper.find('#social-scope').exists()).toBe(false)
    if (strategy === 'waad') {
      expect(wrapper.find<HTMLInputElement>('#microsoft-tenant').element.readOnly).toBe(true)
      expect(wrapper.find<HTMLInputElement>('#microsoft-mode').element.readOnly).toBe(true)
    }
    expect(wrapper.findAll('[data-testid="callbacks"] code').map(c => c.text())).toEqual(['https://acme.example.test/login/callback', 'https://login.acme.com/login/callback', 'https://other.acme.com/login/callback'])
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect((calls.find(c => c.method === 'PATCH')?.body as { options: unknown }).options).toEqual(options)
    await wrapper.find('#social-secret').setValue('   ')
    await wrapper.find('form').trigger('submit')
    expect(wrapper.find('#social-secret-error').exists()).toBe(true)
    expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(1)
    await wrapper.find('#social-secret').setValue('rotated')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect((calls.filter(c => c.method === 'PATCH')[1]?.body as { options: Record<string, unknown> }).options.client_secret).toBe('rotated')
    expect(wrapper.find<HTMLInputElement>('#social-secret').element.value).toBe('')
    wrapper.unmount()
  })

  it('shows the any-organization warning in immutable multitenant settings', async () => {
    const item = connection('con_ms', { strategy: 'waad', options: { client_id: clientId, useCommonEndpoint: true } })
    const { wrapper } = await mountAt(Detail, '/t/acme/enterprise/con_ms', () => ({ status: 200, body: item }))
    expect(wrapper.find('#microsoft-tenant').exists()).toBe(false)
    expect(wrapper.find('[data-testid="any-organization-warning"]').text()).toContain('every organizational directory')
    wrapper.unmount()
  })
})

describe('Apple settings', () => {
  it('keeps Services ID immutable, preserves an omitted key, rotates write-only key and updates scopes', async () => {
    const options = { client_id: 'test.acme.web', team_id: 'ABCDE12345', kid: 'ABCDE67890', name: true, email: true, scope: 'name email' }
    const item = connection('con_apple', { strategy: 'apple', options })
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/social/con_apple', () => ({ status: 200, body: item }))
    expect(wrapper.find<HTMLInputElement>('#social-client-id').element.readOnly).toBe(true)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    const first = (calls.find(c => c.method === 'PATCH')?.body as {options: Record<string, unknown>}).options
    expect(first.app_secret).toBeUndefined(); expect(first.client_secret).toBeUndefined()
    await wrapper.find('#apple-key').setValue('not-a-key')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(1)
    await wrapper.find('#apple-key').setValue(appleKey)
    await wrapper.find('#apple-team').setValue('ABCDE54321')
    await wrapper.find('#apple-kid').setValue('ABCDE09876')
    await wrapper.find('#apple-name').setValue(false)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    const second = (calls.filter(c => c.method === 'PATCH')[1]?.body as {options: Record<string, unknown>}).options
    expect(second).toMatchObject({app_secret: appleKey, team_id: 'ABCDE54321', kid: 'ABCDE09876', name: false, email: true})
    expect(second.scope).toBeUndefined(); expect(second.client_secret).toBeUndefined()
    expect(wrapper.find<HTMLTextAreaElement>('#apple-key').element.value).toBe('')
    wrapper.unmount()
  })
})

describe('GitHub settings', () => {
  it('keeps the client ID read-only, shows the effective scope and the notes, and omits scope and secret on save', async () => {
    const item = connection('con_gh', { strategy: 'github', options: githubOptions })
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/social/con_gh', () => ({ status: 200, body: item }), { domains: ['login.acme.com'] })
    expect(wrapper.find<HTMLInputElement>('#social-client-id').element.readOnly).toBe(true)
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.value).toBe('user:email repo')
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.readOnly).toBe(true)
    expect(wrapper.find<HTMLInputElement>('#github-scope-repo').element.checked).toBe(true)
    expect(wrapper.text()).toContain('A secret is configured')
    expect(wrapper.text()).toContain('GitHub App gets its permissions from its own registration')
    expect(wrapper.find('[data-testid="github-callbacks"]').text()).toContain('Register every listed URL exactly')
    expect(wrapper.findAll('[data-testid="callbacks"] code').map(c => c.text())).toEqual(['https://acme.example.test/login/callback', 'https://login.acme.com/login/callback'])
    await wrapper.find('form').trigger('submit'); await flushPromises()
    const first = (calls.find(c => c.method === 'PATCH')?.body as { options: Record<string, unknown> }).options
    expect(first).toEqual({ client_id: 'Iv1.testclientid0000', email: true, repo: true })
    await wrapper.find('#github-scope-repo').setValue(false)
    await wrapper.find('#github-scope-gist').setValue(true)
    await wrapper.find('#github-email').setValue(false)
    expect(wrapper.find<HTMLInputElement>('#github-effective').element.value).toBe('gist')
    await wrapper.find('#social-secret').setValue('rotated')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    const second = (calls.filter(c => c.method === 'PATCH')[1]?.body as { options: Record<string, unknown> }).options
    expect(second).toEqual({ client_id: 'Iv1.testclientid0000', email: false, gist: true, client_secret: 'rotated' })
    wrapper.unmount()
  })
})
