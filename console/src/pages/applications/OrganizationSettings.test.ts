import { flushPromises, mount } from '@vue/test-utils'
import { expect, it } from 'vitest'
import SettingsTab from './SettingsTab.vue'
import { servicesKey } from '../../context'
import type { Client } from '../../api/client'
import { client, fakeServices, tenant } from '../../test/services'
it('allows pre-login for deny, restricts discovery, and requires OIDC for post-login', async () => {
  const s = fakeServices(() => ({ status: 200, body: client('app') }))
  const wrapper = mount(SettingsTab, { props: { tenant: tenant('acme'), client: ({ ...client('app'), oidc_conformant: false } as unknown as Client) }, global: { plugins: [s.pinia, s.i18n], provide: { [servicesKey as symbol]: s.services } } })
  await wrapper.get('#app-organization-behavior').setValue('pre_login_prompt')
  expect(wrapper.get('#app-organization-behavior option[value="pre_login_prompt"]').attributes('disabled')).toBeUndefined()
  expect(wrapper.get('#app-organization-behavior option[value="post_login_prompt"]').attributes('disabled')).toBeDefined()
  await wrapper.get('#app-organization-discovery-organization_name').setValue(true)
  await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(s.calls.at(-1)!.body).toMatchObject({ organization_usage: 'deny', organization_require_behavior: 'pre_login_prompt', organization_discovery_methods: ['organization_name'] })
  await wrapper.get('#app-organization-behavior').setValue('no_prompt')
  expect(wrapper.get('#app-organization-discovery-organization_name').attributes('disabled')).toBeDefined(); wrapper.unmount()
})
it.each(['deny', 'allow', 'require'] as const)('saves pre-login prompting with %s usage', async usage => {
  const s = fakeServices(() => ({ status: 200, body: client('app') }))
  const wrapper = mount(SettingsTab, { props: { tenant: tenant('acme'), client: client('app') }, global: { plugins: [s.pinia, s.i18n], provide: { [servicesKey as symbol]: s.services } } })
  await wrapper.get('#app-organization-usage').setValue(usage); await wrapper.get('#app-organization-behavior').setValue('pre_login_prompt'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(s.calls.at(-1)!.body).toMatchObject({ organization_usage: usage, organization_require_behavior: 'pre_login_prompt', organization_discovery_methods: null }); wrapper.unmount()
})
it('clears stored discovery when leaving pre-login prompting', async () => {
  const s = fakeServices(() => ({ status: 200, body: client('app') }))
  const wrapper = mount(SettingsTab, { props: { tenant: tenant('acme'), client: client('app', { organization_require_behavior: 'pre_login_prompt', organization_discovery_methods: ['email'] }) }, global: { plugins: [s.pinia, s.i18n], provide: { [servicesKey as symbol]: s.services } } })
  await wrapper.get('#app-organization-behavior').setValue('post_login_prompt'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(s.calls.at(-1)!.body).toMatchObject({ organization_require_behavior: 'post_login_prompt', organization_discovery_methods: null }); wrapper.unmount()
})
it('rejects require usage when password grants are configured', async () => {
  const s = fakeServices(() => ({ status: 200, body: client('app') }))
  const wrapper = mount(SettingsTab, { props: { tenant: tenant('acme'), client: client('app', { grant_types: ['password'] }) }, global: { plugins: [s.pinia, s.i18n], provide: { [servicesKey as symbol]: s.services } } })
  await wrapper.get('#app-organization-usage').setValue('require'); await wrapper.get('form').trigger('submit'); await flushPromises()
  expect(wrapper.text()).toContain('cannot use password'); expect(s.calls).toHaveLength(0); wrapper.unmount()
})
it('ignores a save reply after changing application and resets the organization draft', async () => {
  let resolve!: (value: { status: number; body: Client }) => void
  const s = fakeServices(() => new Promise(r => { resolve = r }))
  const wrapper = mount(SettingsTab, { props: { tenant: tenant('acme'), client: client('old') }, global: { plugins: [s.pinia, s.i18n], provide: { [servicesKey as symbol]: s.services } } })
  await wrapper.get('#app-organization-usage').setValue('require'); await wrapper.get('form').trigger('submit'); await flushPromises()
  await wrapper.setProps({ client: client('new', { organization_usage: 'allow' }) }); resolve({ status: 200, body: client('old', { organization_usage: 'require' }) }); await flushPromises()
  expect((wrapper.get('#app-organization-usage').element as HTMLSelectElement).value).toBe('allow'); expect(wrapper.emitted('saved')).toBeUndefined(); expect(wrapper.text()).not.toContain('Saved'); wrapper.unmount()
})
