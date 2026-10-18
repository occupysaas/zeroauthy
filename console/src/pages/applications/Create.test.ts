import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { client } from '../../test/services'
import Create from './Create.vue'
import { defaultsFor } from './defaults'

describe('Create application', () => {
  it('creates with the type’s defaults and opens the application', async () => {
    const { wrapper, router, calls } = await mountAt(Create, '/t/acme/applications/new', () => ({ status: 201, body: client('new1') }))
    const submit = wrapper.find('button[type="submit"]')
    expect(submit.attributes('disabled')).toBeDefined() // no name yet
    await wrapper.find('#app-name').setValue('My API client')
    await wrapper.find('input[value="non_interactive"]').setValue(true)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls[0]!.method).toBe('POST')
    expect(calls[0]!.body).toEqual({ name: 'My API client', ...defaultsFor('non_interactive') })
    expect(router.currentRoute.value.fullPath).toBe('/t/acme/applications/new1')
    wrapper.unmount()
  })

  it('shows the API’s refusal', async () => {
    const { wrapper, router } = await mountAt(Create, '/t/acme/applications/new', () =>
      apiError(400, 'invalid_body', 'Payload validation error: name: must be 1 to 255 characters'),
    )
    await wrapper.find('#app-name').setValue('x')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.find('[role="alert"]').text()).toContain('must be 1 to 255 characters')
    expect(router.currentRoute.value.name).toBe('application-new')
    wrapper.unmount()
  })

  it('gives every type an explanation', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/applications/new', () => ({ status: 201 }))
    for (const at of ['native', 'spa', 'regular_web', 'non_interactive']) {
      const input = wrapper.find(`input[value="${at}"]`)
      const help = wrapper.find('#' + input.attributes('aria-describedby'))
      expect(help.text().length).toBeGreaterThan(20)
    }
    wrapper.unmount()
  })
})
