import { defineComponent, h, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { resourceServer, tenant, type Reply } from '../../test/services'
import SettingsTab from './SettingsTab.vue'

afterEach(() => {
  document.body.innerHTML = ''
})
it('preserves the RFC base dialect when toggling permission inclusion and retains the dialect with RBAC off', async () => {
  const page = defineComponent({ render: () => h(SettingsTab, { tenant: tenant('acme'), server: resourceServer('r1') }) })
  const { wrapper, calls } = await mountAt(page, '/t/acme/apis/r1', (c) => ({
    status: 200,
    body: { ...resourceServer('r1'), ...(c.body as object) },
  }))
  await wrapper.get('#api-rbac').setValue(true)
  await wrapper.get('#api-profile').setValue('rfc9068_profile')
  await wrapper.get('#api-permissions-claim').setValue(true)
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)!.body).toMatchObject({ enforce_policies: true, token_dialect: 'rfc9068_profile_authz' })
  await wrapper.get('#api-rbac').setValue(false)
  expect(wrapper.get('#api-permissions-claim').attributes('disabled')).toBeDefined()
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)!.body).toMatchObject({ enforce_policies: false, token_dialect: 'rfc9068_profile_authz' })
  wrapper.unmount()
})
it('protects system API RBAC controls and does not submit their values', async () => {
  const page = defineComponent({
    render: () => h(SettingsTab, { tenant: tenant('acme'), server: resourceServer('r1', { is_system: true }) }),
  })
  const { wrapper, calls } = await mountAt(page, '/t/acme/apis/r1', () => ({
    status: 200,
    body: resourceServer('r1', { is_system: true }),
  }))
  for (const id of ['#api-rbac', '#api-profile', '#api-permissions-claim']) expect(wrapper.get(id).attributes('disabled')).toBeDefined()
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)!.body).not.toHaveProperty('enforce_policies')
  expect(calls.at(-1)!.body).not.toHaveProperty('token_dialect')
  wrapper.unmount()
})
it('ignores a saved response arriving after switching tenants', async () => {
  const selected = ref(tenant('acme'))
  let finish!: (r: Reply) => void
  const page = defineComponent({
    render: () => h(SettingsTab, { tenant: selected.value, server: resourceServer('r1', { name: selected.value.name }) }),
  })
  const { wrapper } = await mountAt(
    page,
    '/t/acme/apis/r1',
    () =>
      new Promise((r) => {
        finish = r
      }),
  )
  await wrapper.get('#api-name').setValue('Old save')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  selected.value = tenant('other')
  await flushPromises()
  finish({ status: 200, body: resourceServer('r1', { name: 'Old save' }) })
  await flushPromises()
  expect((wrapper.get('#api-name').element as HTMLInputElement).value).toBe('other')
  expect(wrapper.text()).not.toContain('Saved')
  wrapper.unmount()
})
