import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { client } from '../../test/services'
import List from './List.vue'

describe('Applications list', () => {
  it('shows a page of applications with paging', async () => {
    const all = Array.from({ length: 25 }, (_, i) => client('c' + i, { name: 'App ' + i }))
    const { wrapper, router, calls } = await mountAt(List, '/t/acme/applications', (c) => {
      const u = new URL(c.url)
      const page = Number(u.searchParams.get('page'))
      const per = Number(u.searchParams.get('per_page'))
      return { status: 200, body: { clients: all.slice(page * per, page * per + per), start: page * per, limit: per, total: all.length } }
    })
    expect(calls[0]!.url).toBe('https://acme.example.test/api/v2/clients?page=0&per_page=20&include_totals=true')
    expect(wrapper.findAll('tbody tr')).toHaveLength(20)
    expect(wrapper.text()).toContain('1–20 of 25')
    const next = wrapper.findAll('button').find((b) => b.text() === 'Next')!
    await next.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.page).toBe('1')
    expect(wrapper.findAll('tbody tr')).toHaveLength(5)
    expect(wrapper.text()).toContain('21–25 of 25')
    expect(wrapper.findAll('button').find((b) => b.text() === 'Next')!.attributes('disabled')).toBeDefined()
    wrapper.unmount()
  })

  it('filters by type through the API', async () => {
    const { wrapper, router, calls } = await mountAt(List, '/t/acme/applications', () => ({
      status: 200,
      body: { clients: [], start: 0, limit: 20, total: 0 },
    }))
    expect(wrapper.text()).toContain('No applications yet.')
    await wrapper.find('select').setValue('spa')
    await flushPromises()
    expect(router.currentRoute.value.query.type).toBe('spa')
    expect(calls.at(-1)!.url).toContain('app_type=spa')
    expect(wrapper.text()).toContain('No applications of this type.')
    wrapper.unmount()
  })

  it('reports an error and retries', async () => {
    let fail = true
    const { wrapper } = await mountAt(List, '/t/acme/applications', () =>
      fail ? apiError(500, 'internal_error', 'Internal error') : { status: 200, body: { clients: [client('x')], start: 0, limit: 20, total: 1 } },
    )
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    fail = false
    await wrapper.findAll('button').find((b) => b.text() === 'Try again')!.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    wrapper.unmount()
  })

  it('reports an unknown tenant', async () => {
    const { wrapper } = await mountAt(List, '/t/nope/applications', () => ({ status: 200, body: {} }))
    expect(wrapper.text()).toContain('This tenant does not exist')
    wrapper.unmount()
  })
})
