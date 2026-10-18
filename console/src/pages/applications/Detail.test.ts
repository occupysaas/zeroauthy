import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import type { Client } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import { client } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/applications/abc'

function tabTo(name: string) {
  const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find((t) => t.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}

describe('Application detail', () => {
  it('loads, masks the secret, and reveals it', async () => {
    const { wrapper } = await mountAt(Detail, path, () => ({ status: 200, body: client('abc', { name: 'Billing' }) }))
    expect(wrapper.find('h1').text()).toBe('Billing')
    expect(wrapper.find('[data-testid="client-id"]').text()).toBe('abc')
    const secret = wrapper.find('[data-testid="secret"]')
    expect(secret.text()).not.toContain('SSSS')
    await wrapper.findAll('button').find((b) => b.text() === 'Reveal')!.trigger('click')
    expect(wrapper.find('[data-testid="secret"]').text()).toBe('S'.repeat(64))
    wrapper.unmount()
  })

  it('offers rotate to reveal for a secret it cannot show, and nothing for a public client', async () => {
    let c: Client = client('abc', { client_secret: undefined })
    const { wrapper, router } = await mountAt(Detail, path, () => ({ status: 200, body: c }))
    expect(wrapper.find('[data-testid="rotate-to-reveal"]').exists()).toBe(true)
    c = client('spa', { client_secret: undefined, token_endpoint_auth_method: 'none', app_type: 'spa' })
    await router.push('/t/acme/applications/spa')
    await flushPromises()
    expect(wrapper.text()).toContain('Public applications')
    expect(wrapper.find('[data-testid="secret"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('saves settings and shows field errors from the API', async () => {
    let fail = true
    const { wrapper, calls } = await mountAt(Detail, path, (c) => {
      if (c.method === 'PATCH') {
        return fail
          ? apiError(400, 'invalid_body', 'Payload validation error: callback "nope" must be an absolute URL; web_origins: "x" is not an origin (scheme://host[:port])')
          : { status: 200, body: client('abc', { callbacks: ['https://ok.test/cb'] }) }
      }
      return { status: 200, body: client('abc') }
    })
    await wrapper.find('#app-callbacks').setValue('nope')
    await wrapper.find('#app-webOrigins').setValue('x')
    await wrapper.find('form:not(.danger-zone form)').trigger('submit')
    await flushPromises()
    expect(calls.at(-1)!.body).toMatchObject({ callbacks: ['nope'], web_origins: ['x'] })
    expect(wrapper.find('#app-callbacks-error').text()).toContain('must be an absolute URL')
    expect(wrapper.find('#app-webOrigins-error').text()).toContain('is not an origin')
    expect(wrapper.find('#app-callbacks').attributes('aria-invalid')).toBe('true')
    fail = false
    await wrapper.find('#app-callbacks').setValue('https://ok.test/cb')
    await wrapper.find('#app-webOrigins').setValue('')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('#app-callbacks-error').exists()).toBe(false)
    expect(wrapper.text()).toContain('Saved')
    wrapper.unmount()
  })

  it('reports a missing application and a failing load', async () => {
    const missing = await mountAt(Detail, path, () => apiError(404, 'inexistent_client', 'The client does not exist'))
    expect(missing.wrapper.text()).toContain('There is nothing at this address.')
    missing.wrapper.unmount()
    const failing = await mountAt(Detail, path, () => apiError(500, 'internal_error', 'Internal error'))
    expect(failing.wrapper.text()).toContain('Internal error')
    failing.wrapper.unmount()
  })

  it('saves advanced settings', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, (c) =>
      c.method === 'PATCH' ? { status: 200, body: client('abc', { grant_types: ['client_credentials'] }) } : { status: 200, body: client('abc') },
    )
    tabTo('Advanced')
    await flushPromises()
    const checkbox = (v: string) => document.body.querySelector<HTMLInputElement>(`input[type="checkbox"][value="${v}"]`)!
    expect(checkbox('authorization_code').checked).toBe(true)
    checkbox('authorization_code').click()
    await flushPromises()
    checkbox('refresh_token').click()
    await flushPromises()
    document.body.querySelector<HTMLFormElement>('form')!.dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(calls.at(-1)!.body).toMatchObject({ grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_post' })
    expect(document.body.querySelector('[data-testid="party"]')!.textContent).toContain('First-party')
    wrapper.unmount()
  })

  it('rotates the secret after confirmation', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, (c) =>
      c.url.endsWith('/rotate-secret') ? { status: 200, body: client('abc', { client_secret: 'N'.repeat(64) }) } : { status: 200, body: client('abc') },
    )
    tabTo('Danger zone')
    await flushPromises()
    Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Rotate secret')!.click()
    await flushPromises()
    const dialog = document.body.querySelector('[role="dialog"]')!
    expect(dialog.textContent).toContain('Rotate the secret?')
    Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Rotate secret')!.click()
    await flushPromises()
    expect(calls.at(-1)!.method).toBe('POST')
    expect(calls.at(-1)!.url).toBe('https://acme.example.test/api/v2/clients/abc/rotate-secret')
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    wrapper.unmount()
  })

  it('deletes only once the name is typed', async () => {
    const { wrapper, router, calls } = await mountAt(Detail, path, (c) =>
      c.method === 'DELETE' ? { status: 204 } : { status: 200, body: client('abc', { name: 'Billing' }) },
    )
    tabTo('Danger zone')
    await flushPromises()
    Array.from(document.body.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Delete application')!.click()
    await flushPromises()
    const dialog = document.body.querySelector('[role="dialog"]')!
    const confirm = () => Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Delete application')!
    expect(confirm().disabled).toBe(true)
    const input = dialog.querySelector<HTMLInputElement>('#delete-confirm')!
    input.value = 'Billin'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(confirm().disabled).toBe(true)
    input.value = 'Billing'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(confirm().disabled).toBe(false)
    confirm().click()
    await flushPromises()
    expect(calls.at(-1)!.method).toBe('DELETE')
    expect(router.currentRoute.value.name).toBe('applications')
    wrapper.unmount()
  })
})
