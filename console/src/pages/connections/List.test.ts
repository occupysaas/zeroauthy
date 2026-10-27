import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { connection, type Call } from '../../test/services'
import List from './List.vue'

function backend(all: ReturnType<typeof connection>[]) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections') {
      const page = Number(u.searchParams.get('page'))
      const per = Number(u.searchParams.get('per_page'))
      return { status: 200, body: { connections: all.slice(page * per, page * per + per), start: page * per, limit: per, total: all.length } }
    }
    const m = /^\/api\/v2\/connections\/(.+)\/clients$/.exec(u.pathname)
    if (m) return { status: 200, body: { clients: m[1] === 'c0' ? [{ client_id: 'a' }, { client_id: 'b' }] : [] } }
    return { status: 404 }
  }
}

describe('connections list', () => {
  it('shows a page with strategy and the enabled-application count, and pages', async () => {
    const all = Array.from({ length: 25 }, (_, i) => connection('c' + i))
    const { wrapper, router, calls } = await mountAt(List, '/t/acme/connections', backend(all))
    expect(calls[0]!.url).toBe('https://acme.example.test/api/v2/connections?page=0&per_page=20&include_totals=true')
    expect(wrapper.findAll('tbody tr')).toHaveLength(20)
    expect(wrapper.findAll('tbody tr')[0]!.text()).toContain('Database')
    expect(wrapper.find('[data-testid="count-c0"]').text()).toBe('2')
    expect(wrapper.find('[data-testid="count-c1"]').text()).toBe('0')
    expect(wrapper.text()).toContain('1–20 of 25')
    await wrapper.findAll('button').find((b) => b.text() === 'Next')!.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.page).toBe('1')
    expect(wrapper.findAll('tbody tr')).toHaveLength(5)
    wrapper.unmount()
  })

  it('shows a dash when a count cannot be read', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/connections', (c) =>
      c.url.includes('/clients') ? apiError(500, 'internal_error', 'x') : { status: 200, body: { connections: [connection('c0')], start: 0, limit: 20, total: 1 } },
    )
    expect(wrapper.find('[data-testid="count-c0"]').text()).toBe('—')
    wrapper.unmount()
  })

  it('shows an empty state with a way to create one', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/connections', () => ({ status: 200, body: { connections: [], start: 0, limit: 20, total: 0 } }))
    expect(wrapper.text()).toContain('No connections yet.')
    expect(wrapper.find('a.create').attributes('href')).toBe('/admin/t/acme/connections/new')
    wrapper.unmount()
  })

  it('reports an error and retries', async () => {
    let fail = true
    const { wrapper } = await mountAt(List, '/t/acme/connections', (c) =>
      fail ? apiError(500, 'internal_error', 'Internal error') : backend([connection('c0')])(c),
    )
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    fail = false
    await wrapper.findAll('button').find((b) => b.text() === 'Try again')!.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    wrapper.unmount()
  })

  it('says Loading while the request is pending', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/connections', () => new Promise(() => undefined))
    expect(wrapper.find('[role="status"]').text()).toBe('Loading…')
    wrapper.unmount()
  })

  it('reports an unknown tenant', async () => {
    const { wrapper } = await mountAt(List, '/t/nope/connections', () => ({ status: 200, body: {} }))
    expect(wrapper.text()).toContain('This tenant does not exist')
    wrapper.unmount()
  })
})


it('routes federated connections to their shared social or enterprise forms from the overall list', async () => {
  const strategies = ['auth0', 'google-oauth2', 'oauth2', 'oidc', 'windowslive', 'waad']
  const { wrapper } = await mountAt(List, '/t/acme/connections', backend(strategies.map(strategy => connection(strategy, { name: strategy, strategy, options: {} }))))
  expect(wrapper.findAll('tbody a').map(a => a.attributes('href'))).toEqual([
    '/admin/t/acme/connections/auth0', '/admin/t/acme/social/google-oauth2', '/admin/t/acme/social/oauth2', '/admin/t/acme/enterprise/oidc', '/admin/t/acme/social/windowslive', '/admin/t/acme/enterprise/waad',
  ])
  expect(wrapper.text()).toContain('Microsoft personal account')
  expect(wrapper.text()).toContain('Microsoft work or school account')
  wrapper.unmount()
})
