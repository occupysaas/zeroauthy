import { defineComponent, h } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { tenant } from '../../../test/services'
import DirectorySync from './DirectorySync.vue'
afterEach(() => {
  document.body.innerHTML = ''
})
const conn = { id: 'con_ws1', name: 'workspace', strategy: 'google-apps', is_domain_connection: false }
const cfg = { connection_id: 'con_ws1', connection_name: 'workspace', strategy: 'google-apps', mapping: [{ auth0: 'email', idp: 'primaryEmail' }],
  synchronize_automatically: false, synchronize_groups: 'off', created_at: '2026-11-23T00:00:00Z', updated_at: '2026-11-23T00:00:00Z' }
it('enables directory provisioning, gets a consent link and requests a synchronization', async () => {
  let enabled = false
  const page = defineComponent({ render: () => h(DirectorySync, { tenant: tenant('acme'), connection: conn }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/enterprise', (c) => {
    if (c.url.endsWith('/directory-provisioning/consent')) return { status: 200, body: { url: 'https://acme.example.test/directory-provisioning/consent?ticket=t1', redirect_uri: 'x', expires_at: '2026-11-23T00:15:00Z' } }
    if (c.url.endsWith('/synchronizations')) return { status: 201, body: { connection_id: 'con_ws1', synchronization_id: 'dsync_1', status: 'pending' } }
    if (c.url.includes('/synchronized-groups')) return { status: 200, body: { groups: [] } }
    if (c.method === 'POST') {
      enabled = true
      return { status: 201, body: cfg }
    }
    return enabled ? { status: 200, body: { ...cfg, last_synchronization_at: '2026-11-23T01:00:00Z', last_synchronization_status: 'failed', last_synchronization_error: 'a Google Workspace administrator has not authorized directory access' } } : { status: 404, body: { statusCode: 404, error: 'Not Found', message: 'none' } }
  })
  expect(wrapper.text()).toContain('Directory provisioning is off')
  await wrapper.get('[data-testid="dirsync-enable"]').trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('https://acme.example.test/directory-provisioning/callback')
  await wrapper.get('[data-testid="dirsync-authorize"]').trigger('click')
  await flushPromises()
  const consentCall = calls.find((c) => c.url.endsWith('/directory-provisioning/consent'))!
  expect(consentCall.url).toContain('/api/system/tenants/acme/connections/con_ws1/directory-provisioning/consent')
  expect(wrapper.get('[data-testid="dirsync-consent"]').attributes('href')).toBe('https://acme.example.test/directory-provisioning/consent?ticket=t1')
  await wrapper.get('[data-testid="dirsync-sync"]').trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('Synchronization requested.')
  wrapper.unmount()
})
it('saves automatic runs, selected groups and the mapping', async () => {
  const page = defineComponent({ render: () => h(DirectorySync, { tenant: tenant('acme'), connection: conn }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/enterprise', (c) => {
    if (c.url.includes('/synchronized-groups')) return c.method === 'PUT' ? { status: 204 } : { status: 200, body: { groups: [{ id: '03abc', name: 'Engineering' }] } }
    return { status: 200, body: c.method === 'PATCH' ? { ...cfg, synchronize_automatically: true, synchronize_groups: 'selected' } : cfg }
  })
  await wrapper.get('input[type="checkbox"]').setValue(true)
  await wrapper.get('#dirsync-groups').setValue('selected')
  await wrapper.get('#dirsync-group-ids').setValue('03abc\n04def')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.find((c) => c.method === 'PATCH')!.body).toEqual({ mapping: cfg.mapping, synchronize_automatically: true, synchronize_groups: 'selected' })
  expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({ groups: [{ id: '03abc', name: 'Engineering' }, { id: '04def' }] })
  wrapper.unmount()
})
