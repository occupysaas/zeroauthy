import { DOMWrapper, flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import type { Call } from '../../test/services'
import TokenExchangeProfiles from './TokenExchangeProfiles.vue'

// The profile form is a dialog, rendered in a portal on the body.
const dom = () => new DOMWrapper(document.body)
const path = '/t/acme/actions/token-exchange-profiles'
const action = (id: string, deployed: boolean) => ({ id, name: 'Exchange ' + id, supported_triggers: [{ id: 'custom-token-exchange' }], deployed_version: deployed ? { id: 'v1' } : undefined })
const profile = (id: string) => ({ id, name: 'Profile ' + id, subject_token_type: 'urn:example:' + id + '-token', action_id: 'act1', type: 'custom_authentication', created_at: '', updated_at: '' })

function handler(list: ReturnType<typeof profile>[]) {
  return (c: Call) => {
    if (c.url.includes('/actions/actions')) return { status: 200, body: { actions: [action('act1', true), action('act2', false)], total: 2, page: 0, per_page: 100 } }
    if (c.method === 'POST') { list.push(profile('tep_new')); return { status: 201, body: profile('tep_new') } }
    if (c.method === 'DELETE') { list.splice(0, 1); return { status: 204 } }
    return { status: 200, body: { token_exchange_profiles: list } }
  }
}

afterEach(() => { document.body.innerHTML = '' })

describe('Token exchange profiles', () => {
  it('lists profiles with their Action', async () => {
    const { wrapper } = await mountAt(TokenExchangeProfiles, path, handler([profile('tep_a')]))
    expect(wrapper.text()).toContain('Profile tep_a')
    expect(wrapper.text()).toContain('Exchange act1')
    wrapper.unmount()
  })

  it('creates a profile choosing from deployed custom-token-exchange Actions only', async () => {
    const list: ReturnType<typeof profile>[] = []
    const { wrapper, calls } = await mountAt(TokenExchangeProfiles, path, handler(list))
    expect(calls.find((c) => c.url.includes('/actions/actions'))!.url).toContain('triggerId=custom-token-exchange')
    await wrapper.findAll('button').find((b) => b.text() === 'Create profile')!.trigger('click')
    await flushPromises()
    const options = Array.from(document.querySelectorAll<HTMLOptionElement>('#tep-action option')).map((o) => o.textContent?.trim())
    expect(options).toContain('Exchange act1')
    expect(options).not.toContain('Exchange act2')
    await dom().find('#tep-name').setValue('Partner login')
    await dom().find('#tep-type').setValue('urn:example:partner')
    await dom().find('#tep-action').setValue('act1')
    await dom().find('[role="dialog"] form').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ name: 'Partner login', subject_token_type: 'urn:example:partner', action_id: 'act1', type: 'custom_authentication' })
    expect(wrapper.text()).toContain('Profile tep_new')
    wrapper.unmount()
  })

  it('validates before calling the API', async () => {
    const { wrapper, calls } = await mountAt(TokenExchangeProfiles, path, handler([]))
    await wrapper.findAll('button').find((b) => b.text() === 'Create profile')!.trigger('click')
    await flushPromises()
    await dom().find('#tep-name').setValue('ab')
    await dom().find('#tep-type').setValue('http://short')
    await dom().find('[role="dialog"] form').trigger('submit')
    expect(dom().find('#tep-name-error').text()).toContain('3 to 50')
    expect(dom().find('#tep-type-error').text()).toContain('https:// or urn:')
    expect(dom().find('#tep-action-error').exists()).toBe(true)
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    wrapper.unmount()
  })

  it('shows a duplicate subject token type on its field', async () => {
    const { wrapper } = await mountAt(TokenExchangeProfiles, path, (c) => c.method === 'POST' ? apiError(409, 'token_exchange_profile_conflict', 'A token exchange profile with this subject_token_type already exists') : handler([])(c))
    await wrapper.findAll('button').find((b) => b.text() === 'Create profile')!.trigger('click')
    await flushPromises()
    await dom().find('#tep-name').setValue('Partner login')
    await dom().find('#tep-type').setValue('urn:example:partner')
    await dom().find('#tep-action').setValue('act1')
    await dom().find('[role="dialog"] form').trigger('submit')
    await flushPromises()
    expect(dom().find('#tep-type-error').text()).toContain('already exists')
    wrapper.unmount()
  })

  it('edits only name and subject token type', async () => {
    const { wrapper, calls } = await mountAt(TokenExchangeProfiles, path, (c) => c.method === 'PATCH' ? { status: 200, body: profile('tep_a') } : handler([profile('tep_a')])(c))
    await wrapper.findAll('button').find((b) => b.text() === 'Edit')!.trigger('click')
    await flushPromises()
    expect(dom().find('#tep-action').attributes('disabled')).toBeDefined()
    await dom().find('#tep-name').setValue('Renamed')
    await dom().find('[role="dialog"] form').trigger('submit')
    await flushPromises()
    const patch = calls.find((c) => c.method === 'PATCH')!
    expect(patch.url).toBe('https://acme.example.test/api/v2/token-exchange-profiles/tep_a')
    expect(patch.body).toEqual({ name: 'Renamed', subject_token_type: 'urn:example:tep_a-token' })
    wrapper.unmount()
  })

  it('deletes after confirmation', async () => {
    const { wrapper, calls } = await mountAt(TokenExchangeProfiles, path, handler([profile('tep_a')]))
    await wrapper.findAll('button').find((b) => b.text() === 'Delete')!.trigger('click')
    await flushPromises()
    document.querySelector<HTMLButtonElement>('[data-testid="confirm-delete"]')!.click()
    await flushPromises()
    expect(calls.find((c) => c.method === 'DELETE')!.url).toBe('https://acme.example.test/api/v2/token-exchange-profiles/tep_a')
    expect(wrapper.text()).toContain('No token exchange profiles yet')
    wrapper.unmount()
  })
})
