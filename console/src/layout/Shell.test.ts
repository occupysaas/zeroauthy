import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { servicesKey } from '../context'
import { fakeServices, memoryRouter, tenant } from '../test/services'
import Shell from './Shell.vue'

async function sidebar(path: string): Promise<string[]> {
  const { services } = fakeServices((c) =>
    c.url.endsWith('/api/system/tenants') ? { status: 200, body: [tenant('acme'), tenant('system', { reserved: true })] } : { status: 404 },
  )
  await services.tenants.load()
  const router = memoryRouter()
  await router.push(path)
  const wrapper = mount(Shell, { attachTo: document.body, global: { plugins: [router], provide: { [servicesKey as symbol]: services } } })
  await flushPromises()
  const labels = Array.from(wrapper.findAll('nav[aria-label="Sections"] a')).map((a) => a.text())
  wrapper.unmount()
  return labels
}

describe('Shell sidebar', () => {
  it('lists Operators only on the system tenant', async () => {
    expect(await sidebar('/t/acme/')).toEqual(['Home', 'Applications', 'APIs', 'Connections'])
    expect(await sidebar('/t/system/')).toEqual(['Home', 'Applications', 'APIs', 'Connections', 'Operators'])
  })
})
