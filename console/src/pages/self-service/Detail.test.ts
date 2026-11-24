import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import Detail from './Detail.vue'
afterEach(() => {
  document.body.innerHTML = ''
})
const profile = { id: 'ssp_1', name: 'Partners', allowed_strategies: ['samlp'], created_at: '2026-11-23T00:00:00Z', updated_at: '2026-11-23T00:00:00Z' }
it('saves the profile with its introduction and shows a new ticket once', async () => {
  const { wrapper, calls } = await mountAt(Detail, '/t/acme/self-service/ssp_1', (c) => {
    if (c.url.includes('/custom-text/')) return { status: 200, body: c.method === 'PUT' ? c.body : { introduction: 'Hi' } }
    if (c.url.endsWith('/sso-ticket')) return { status: 201, body: { ticket: 'https://acme.example.test/self-service/connections-flow?ticket=abc' } }
    if (c.url.includes('/revoke')) return { status: 202 }
    return { status: 200, body: profile }
  })
  expect((wrapper.get('#ssso-intro').element as HTMLTextAreaElement).value).toBe('Hi')
  await wrapper.get('#ssso-color').setValue('#0a7')
  await wrapper.findAll('form')[0].trigger('submit')
  await flushPromises()
  const patch = calls.find((c) => c.method === 'PATCH')!
  expect(patch.body).toMatchObject({ name: 'Partners', allowed_strategies: ['samlp'], branding: { colors: { primary: '#0a7' } }, description: null })
  expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({ introduction: 'Hi' })
  await wrapper.get('#ssso-new-conn').setValue('acme-sso')
  await wrapper.get('#ssso-clients').setValue('app1, app2')
  await wrapper.findAll('form')[1].trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.url.endsWith('/sso-ticket'))!.body).toEqual({ connection_config: { name: 'acme-sso' }, enabled_clients: ['app1', 'app2'] })
  expect(wrapper.get('[data-testid="ssso-ticket"]').text()).toContain('ticket=abc')
  await wrapper.get('#ssso-revoke').setValue('abc')
  await wrapper.findAll('form')[2].trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.url.includes('/revoke'))!.url).toContain('/sso-ticket/abc/revoke')
  wrapper.unmount()
})
