import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { resourceServer } from '../../test/services'
import List from './List.vue'

describe('APIs list', () => {
  it('shows a page of APIs with paging and marks the system API', async () => {
    const all = [
      resourceServer('sys', { name: 'zeroauthy Management API', is_system: true }),
      ...Array.from({ length: 24 }, (_, i) => resourceServer('r' + i)),
    ]
    const { wrapper, router, calls } = await mountAt(List, '/t/acme/apis', (c) => {
      const u = new URL(c.url)
      const page = Number(u.searchParams.get('page'))
      const per = Number(u.searchParams.get('per_page'))
      return { status: 200, body: { resource_servers: all.slice(page * per, page * per + per), start: page * per, limit: per, total: all.length } }
    })
    expect(calls[0]!.url).toBe('https://acme.example.test/api/v2/resource-servers?page=0&per_page=20&include_totals=true')
    expect(wrapper.findAll('tbody tr')).toHaveLength(20)
    expect(wrapper.find('[data-testid="system-badge"]').text()).toBe('System')
    expect(wrapper.findAll('[data-testid="system-badge"]')).toHaveLength(1)
    expect(wrapper.text()).toContain('1–20 of 25')
    await wrapper.findAll('button').find((b) => b.text() === 'Next')!.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.page).toBe('1')
    expect(wrapper.findAll('tbody tr')).toHaveLength(5)
    expect(wrapper.text()).toContain('21–25 of 25')
    expect(wrapper.find('[data-testid="system-badge"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('shows an empty state with a way to create one', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/apis', () => ({ status: 200, body: { resource_servers: [], start: 0, limit: 20, total: 0 } }))
    expect(wrapper.text()).toContain('No APIs yet.')
    expect(wrapper.find('a.create').attributes('href')).toBe('/admin/t/acme/apis/new')
    wrapper.unmount()
  })

  it('shows the loading state, then reports an error and retries', async () => {
    let fail = true
    const { wrapper } = await mountAt(List, '/t/acme/apis', () =>
      fail ? apiError(500, 'internal_error', 'Internal error') : { status: 200, body: { resource_servers: [resourceServer('x')], start: 0, limit: 20, total: 1 } },
    )
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    fail = false
    await wrapper.findAll('button').find((b) => b.text() === 'Try again')!.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    wrapper.unmount()
  })

  it('says Loading while the request is pending', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/apis', () => new Promise(() => undefined))
    expect(wrapper.find('[role="status"]').text()).toBe('Loading…')
    wrapper.unmount()
  })

  it('reports an unknown tenant', async () => {
    const { wrapper } = await mountAt(List, '/t/nope/apis', () => ({ status: 200, body: {} }))
    expect(wrapper.text()).toContain('This tenant does not exist')
    wrapper.unmount()
  })
})
