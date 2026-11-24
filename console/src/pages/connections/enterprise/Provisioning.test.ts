import { defineComponent, h } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { tenant } from '../../../test/services'
import Provisioning from './Provisioning.vue'
afterEach(() => {
  document.body.innerHTML = ''
})
const conn = { id: 'con_okta1', name: 'corp', strategy: 'okta', is_domain_connection: false }
const cfg = { tenant_name: 'acme', connection_id: 'con_okta1', connection_name: 'corp', strategy: 'okta', user_id_attribute: 'externalId',
  mapping: [{ auth0: 'email', scim: 'emails[primary eq true].value' }], created_at: '2026-11-23T00:00:00Z', updated_on: '2026-11-23T00:00:00Z' }
it('enables SCIM, shows a new token once and revokes it', async () => {
  let enabled = false
  let tokens: object[] = []
  const page = defineComponent({ render: () => h(Provisioning, { tenant: tenant('acme'), connection: conn }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/enterprise', (c) => {
    if (c.url.includes('/tokens/')) {
      tokens = []
      return { status: 204 }
    }
    if (c.url.endsWith('/tokens') && c.method === 'POST') {
      tokens = [{ token_id: 'tok_1', scopes: ['get:users'], created_at: '2026-11-23T00:00:00Z' }]
      return { status: 201, body: { ...tokens[0], token: 'secret-value-shown-once' } }
    }
    if (c.url.endsWith('/tokens')) return { status: 200, body: tokens }
    if (c.method === 'POST') {
      enabled = true
      return { status: 201, body: cfg }
    }
    return enabled ? { status: 200, body: cfg } : { status: 404, body: { statusCode: 404, error: 'Not Found', message: 'none' } }
  })
  expect(wrapper.text()).toContain('SCIM provisioning is off')
  await wrapper.get('[data-testid="scim-enable"]').trigger('click')
  await flushPromises()
  expect((wrapper.get('#scim-endpoint').element as HTMLInputElement).value).toBe('https://acme.example.test/scim/v2/connections/con_okta1')
  expect((wrapper.get('#scim-uid').element as HTMLInputElement).value).toBe('externalId')
  // Narrow the scopes to get:users and generate a token.
  for (const box of wrapper.findAll('input[type="checkbox"]')) if ((box.element as HTMLInputElement).value !== 'get:users') await box.setValue(false)
  await wrapper.get('[data-testid="scim-generate"]').trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'POST' && c.url.endsWith('/tokens'))!.body).toEqual({ scopes: ['get:users'] })
  expect(wrapper.get('[data-testid="scim-secret"]').text()).toBe('secret-value-shown-once')
  expect(wrapper.text()).toContain('tok_1')
  await wrapper.findAll('button').find((b) => b.text() === 'Revoke')!.trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'DELETE')!.url).toContain('/scim-configuration/tokens/tok_1')
  expect(wrapper.text()).toContain('No tokens')
  wrapper.unmount()
})
it('saves the mapping with PATCH', async () => {
  const page = defineComponent({ render: () => h(Provisioning, { tenant: tenant('acme'), connection: conn }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/enterprise', (c) => {
    if (c.url.endsWith('/tokens')) return { status: 200, body: [] }
    return { status: 200, body: c.method === 'PATCH' ? { ...cfg, user_id_attribute: 'userName' } : cfg }
  })
  await wrapper.get('#scim-uid').setValue('userName')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'PATCH')!.body).toEqual({ user_id_attribute: 'userName', mapping: cfg.mapping })
  wrapper.unmount()
})
