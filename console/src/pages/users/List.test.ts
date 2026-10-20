import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import type { User } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import { connection, type Call } from '../../test/services'
import List from './List.vue'

function user(id: string, extra: Partial<User> = {}): User {
  return { user_id: 'auth0|' + id, email: id + '@example.test', identities: [{ connection: 'Users c0', user_id: id, provider: 'auth0', isSocial: false }], logins_count: 0, ...extra }
}

function backend(all: User[]) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections') return { status: 200, body: { connections: [connection('c0')], start: 0, limit: 100, total: 1 } }
    if (u.pathname === '/api/v2/users') {
      const page = Number(u.searchParams.get('page'))
      const per = Number(u.searchParams.get('per_page'))
      return { status: 200, body: { users: all.slice(page * per, page * per + per), start: page * per, limit: per, length: 0, total: all.length } }
    }
    return { status: 404 }
  }
}
const usersCalls = (calls: Call[]) => calls.filter((c) => new URL(c.url).pathname === '/api/v2/users')

describe('users list', () => {
  it('shows the columns and pages on the server', async () => {
    const all = Array.from({ length: 25 }, (_, i) => user('u' + i, i === 0 ? { name: 'Ada', blocked: true, logins_count: 7, last_login: new Date(Date.now() - 3 * 86400000).toISOString() } : {}))
    const { wrapper, router, calls } = await mountAt(List, '/t/acme/users', backend(all))
    const first = new URL(usersCalls(calls)[0]!.url)
    expect(first.searchParams.get('search_engine')).toBe('v3')
    expect(first.searchParams.get('include_totals')).toBe('true')
    expect(first.searchParams.get('per_page')).toBe('20')
    expect(wrapper.findAll('thead th').map((x) => x.text())).toEqual(['Name and email', 'Connection', 'Logins', 'Last login'])
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(20)
    expect(rows[0]!.text()).toContain('Ada')
    expect(rows[0]!.text()).toContain('Blocked')
    expect(rows[0]!.text()).toContain('Users c0')
    expect(rows[0]!.text()).toContain('7')
    expect(rows[0]!.text()).toContain('3 days ago')
    expect(rows[0]!.get('time').attributes('title')).toBeTruthy()
    expect(rows[1]!.text()).toContain('Never')
    expect(wrapper.text()).toContain('1–20 of 25')
    await wrapper.findAll('button').find((b) => b.text() === 'Next')!.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.page).toBe('1')
    expect(wrapper.findAll('tbody tr')).toHaveLength(5)
    wrapper.unmount()
  })

  it('sends the search text unchanged, URL-encoded', async () => {
    const { wrapper, calls } = await mountAt(List, '/t/acme/users', backend([]))
    const text = 'email:"a+b@x.io" AND name:Zoë &x=1'
    await wrapper.get('#users-search').setValue(text)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    const last = usersCalls(calls).at(-1)!.url
    expect(new URL(last).searchParams.get('q')).toBe(text)
    expect(last).not.toContain(' ')
    expect(last).not.toContain('&x=1')
    wrapper.unmount()
  })

  it('sorts by clicking a column and filters by connection', async () => {
    const { wrapper, calls } = await mountAt(List, '/t/acme/users', backend([user('a')]))
    await wrapper.findAll('thead button')[2]!.trigger('click')
    await flushPromises()
    expect(new URL(usersCalls(calls).at(-1)!.url).searchParams.get('sort')).toBe('last_login:1')
    expect(wrapper.findAll('thead th')[3]!.attributes('aria-sort')).toBe('ascending')
    await wrapper.findAll('thead button')[2]!.trigger('click')
    await flushPromises()
    expect(new URL(usersCalls(calls).at(-1)!.url).searchParams.get('sort')).toBe('last_login:-1')
    await wrapper.get('#users-connection').setValue('Users c0')
    await flushPromises()
    expect(new URL(usersCalls(calls).at(-1)!.url).searchParams.get('connection')).toBe('Users c0')
    wrapper.unmount()
  })

  it('shows a refused search under the box', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/users?q=name%3A(', (c) =>
      c.url.includes('/api/v2/users') ? { status: 400, body: { statusCode: 400, error: 'Bad Request', message: 'invalid query: unbalanced parentheses' } } : backend([])(c),
    )
    expect(wrapper.get('#users-search-error').text()).toContain('invalid query')
    expect(wrapper.get('#users-search').attributes('aria-invalid')).toBe('true')
    expect(wrapper.find('table').exists()).toBe(false)
    wrapper.unmount()
  })

  it('shows the empty states', async () => {
    const a = await mountAt(List, '/t/acme/users', backend([]))
    expect(a.wrapper.text()).toContain('No users yet.')
    expect(a.wrapper.find('a.create').attributes('href')).toBe('/admin/t/acme/users/new')
    a.wrapper.unmount()
    const b = await mountAt(List, '/t/acme/users?q=zzz', backend([]))
    expect(b.wrapper.text()).toContain('No user matches this search.')
    b.wrapper.unmount()
  })

  it('reports an error and retries', async () => {
    let fail = true
    const { wrapper } = await mountAt(List, '/t/acme/users', (c) => (fail && c.url.includes('/api/v2/users') ? apiError(500, 'internal_error', 'Internal error') : backend([user('a')])(c)))
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    fail = false
    await wrapper.findAll('button').find((b) => b.text() === 'Try again')!.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    wrapper.unmount()
  })

  it('says Loading while the request is pending', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/users', (c) => (c.url.includes('/api/v2/users') ? new Promise(() => undefined) : backend([])(c)))
    expect(wrapper.find('[role="status"]').text()).toBe('Loading…')
    wrapper.unmount()
  })

  it('stops paging at the 1000 result depth', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/users?page=49', (c) =>
      c.url.includes('/api/v2/users') ? { status: 200, body: { users: [user('a')], start: 980, limit: 20, length: 1, total: 5000 } } : backend([])(c),
    )
    expect(wrapper.findAll('button').find((b) => b.text() === 'Next')!.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('first 1000')
    wrapper.unmount()
  })

  it('opens the query help with a link to the guide', async () => {
    const { wrapper } = await mountAt(List, '/t/acme/users', backend([]))
    expect(wrapper.find('#search-help').exists()).toBe(false)
    await wrapper.findAll('button').find((b) => b.text() === 'Example queries')!.trigger('click')
    expect(wrapper.get('#search-help').text()).toContain('blocked:true')
    expect(wrapper.get('#search-help a').attributes('href')).toMatch(/docs\/user-search\.md$/)
    wrapper.unmount()
  })

  it('ignores an older answer that arrives after a newer one', async () => {
    let releaseOld = () => {}
    const old = new Promise<void>((r) => (releaseOld = r))
    const { wrapper, router } = await mountAt(List, '/t/acme/users?q=old', async (c) => {
      const u = new URL(c.url)
      if (u.pathname === '/api/v2/users') {
        if (u.searchParams.get('q') === 'old') await old
        const who = u.searchParams.get('q') === 'old' ? 'olduser' : 'newuser'
        return { status: 200, body: { users: [user(who)], start: 0, limit: 20, length: 1, total: 1 } }
      }
      return backend([])(c)
    })
    await router.push('/t/acme/users?q=new')
    await flushPromises()
    expect(wrapper.text()).toContain('newuser@')
    releaseOld()
    await flushPromises()
    expect(wrapper.text()).toContain('newuser@')
    expect(wrapper.text()).not.toContain('olduser@')
    wrapper.unmount()
  })
})
