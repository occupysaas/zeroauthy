import { flushPromises } from '@vue/test-utils'
import { getActivePinia } from 'pinia'
import { nextTick } from 'vue'
import { afterEach, describe, expect, it } from 'vitest'
import type { User, UserGrant, UserRefreshToken, UserSession } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import type { Call, Reply } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/users/auth0%7Cabc'
const body = () => document.body
const q = <T extends Element = HTMLElement>(sel: string) => body().querySelector<T>(sel)!

function tabTo(name: string) {
  const trigger = Array.from(body().querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}
function button(label: string, root: ParentNode = body()): HTMLButtonElement {
  return Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
}
function setInput(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  el.value = value
  el.dispatchEvent(new Event('input'))
}
async function click(el: Element) {
  await nextTick() // let earlier input settle into the DOM (disabled states)
  el.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  await flushPromises()
}
async function tab(name: string) {
  tabTo(name)
  await flushPromises()
}

function user(extra: Partial<User> = {}): User {
  return {
    user_id: 'auth0|abc',
    email: 'ada@example.test',
    email_verified: true,
    name: 'Ada Lovelace',
    nickname: 'ada',
    phone_number: '+15550100',
    created_at: '2026-10-01T10:00:00Z',
    updated_at: '2026-10-02T10:00:00Z',
    logins_count: 3,
    user_metadata: { theme: 'dark', color: 'red', prefs: { a: 1 } },
    app_metadata: { plan: 'pro' },
    identities: [{ connection: 'Users c0', user_id: 'abc', provider: 'auth0', isSocial: false }],
    ...extra,
  }
}
const session = (id: string): UserSession => ({
  id,
  user_id: 'auth0|abc',
  created_at: '2026-10-01T10:00:00Z',
  updated_at: '2026-10-01T10:00:00Z',
  authenticated_at: '2026-10-01T10:00:00Z',
  authentication: { methods: [{ name: 'pwd', timestamp: '2026-10-01T10:00:00Z' }] },
  idle_expires_at: '2026-10-09T10:00:00Z',
  expires_at: '2026-10-20T10:00:00Z',
  device: { initial_user_agent: 'Firefox', initial_ip: '10.0.0.1', last_user_agent: 'Firefox', last_ip: '10.0.0.2' },
  clients: [{ client_id: 'cli1' }],
  last_interacted_at: '2026-10-01T10:00:00Z',
  cookie: { mode: 'persistent' },
})
const token = (id: string): UserRefreshToken => ({
  id,
  user_id: 'auth0|abc',
  created_at: '2026-10-01T10:00:00Z',
  idle_expires_at: null,
  expires_at: null,
  client_id: 'cli1',
  session_id: null,
  rotating: false,
  resource_servers: [{ audience: 'https://api.test/', scopes: 'read write' }],
  last_exchanged_at: null,
})
const grant = (id: string): UserGrant => ({ id, clientID: 'cli1', user_id: 'auth0|abc', audience: 'https://api.test/', scope: ['read', 'write'] })

interface World {
  user: User
  sessions: UserSession[]
  tokens: UserRefreshToken[]
  grants: UserGrant[]
  pages?: boolean
  fail?: Record<string, Reply>
  patch?: (c: Call) => Reply
  search?: User[]
}
function world(extra: Partial<World> = {}) {
  const w: World = { user: user(), sessions: [], tokens: [], grants: [], ...extra }
  const handler = (c: Call): Reply => {
    const u = new URL(c.url)
    const key = c.method + ' ' + decodeURIComponent(u.pathname)
    if (w.fail?.[key]) return w.fail[key]!
    switch (key) {
      case 'GET /api/v2/users/auth0|abc':
        return { status: 200, body: w.user }
      case 'PATCH /api/v2/users/auth0|abc':
        if (w.patch) return w.patch(c)
        w.user = { ...w.user, ...(c.body as object) }
        return { status: 200, body: w.user }
      case 'DELETE /api/v2/users/auth0|abc':
        return { status: 204 }
      case 'GET /api/v2/users':
        return { status: 200, body: { users: w.search ?? [], start: 0, limit: 20, total: (w.search ?? []).length } }
      case 'GET /api/v2/users/auth0|abc/sessions': {
        const from = u.searchParams.get('from')
        const list = from ? w.sessions.slice(Number(from)) : w.sessions.slice(0, Number(u.searchParams.get('take')))
        return { status: 200, body: { sessions: list, ...(list.length ? { next: String(w.sessions.indexOf(list[list.length - 1]!) + 1) } : {}) } }
      }
      case 'GET /api/v2/users/auth0|abc/refresh-tokens':
        return { status: 200, body: { tokens: w.tokens, ...(w.tokens.length ? { next: 'n' } : {}) } }
      case 'GET /api/v2/grants':
        return { status: 200, body: w.grants }
      case 'POST /api/v2/tickets/password-change':
        return { status: 201, body: { ticket: 'https://acme.example.test/lo/reset?ticket=SECRETRESET' } }
      case 'POST /api/v2/tickets/email-verification':
        return { status: 201, body: { ticket: 'https://acme.example.test/lo/verify?ticket=SECRETVERIFY' } }
      case 'POST /api/v2/jobs/verification-email':
        return { status: 201, body: { id: 'job_abcdefgh12345678', type: 'verification_email', status: 'pending', created_at: '2026-10-20T10:00:00.000Z' } }
      case 'POST /api/v2/users/auth0|abc/identities':
        return { status: 201, body: [...(w.user.identities ?? []), { connection: 'Users c0', user_id: 'zed', provider: 'auth0', isSocial: false, profileData: { email: 'zed@example.test' } }] }
      case 'DELETE /api/v2/users/auth0|abc/identities/auth0/zed':
        return { status: 200, body: w.user.identities!.slice(0, 1) }
    }
    if (c.method === 'DELETE' && /\/(sessions|refresh-tokens|grants)(\/|$)/.test(u.pathname)) return { status: 202, body: {} }
    return { status: 404 }
  }
  return { w, handler }
}
// gated holds back the answer to any request whose URL contains part until
// release is called, so a test can look at the loading state.
function gated(handler: (c: Call) => Reply, part: string) {
  let release = () => {}
  const gate = new Promise<void>((r) => (release = r))
  return {
    release,
    handler: async (c: Call): Promise<Reply> => {
      if (c.method === 'GET' && c.url.includes(part)) await gate
      return handler(c)
    },
  }
}
const writes = (calls: Call[]) => calls.filter((c) => c.method !== 'GET')

afterEach(() => {
  body().innerHTML = ''
})

describe('user detail', () => {
  it('shows the profile, with the phone as stored only, and saves only what changed', async () => {
    const { handler } = world()
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    expect(wrapper.find('h1').text()).toBe('Ada Lovelace')
    expect(wrapper.text()).toContain('ada@example.test')
    expect(wrapper.text()).toContain('auth0|abc')
    expect(wrapper.get('[data-testid="phone"]').text()).toContain('+15550100')
    expect(wrapper.get('[data-testid="phone"]').text()).toContain('Stored only')
    expect(wrapper.find('#user-phone').exists()).toBe(false)
    await wrapper.get('#user-nickname').setValue('countess')
    await wrapper.get('#user-profile').trigger('submit')
    await flushPromises()
    expect(writes(calls)).toHaveLength(1)
    expect(writes(calls)[0]!.body).toEqual({ nickname: 'countess' })
    expect(wrapper.text()).toContain('Saved')
    wrapper.unmount()
  })

  it('does not save a profile with no changes, and shows the API error', async () => {
    const { handler } = world({ patch: () => apiError(400, 'invalid_body', 'Payload validation error: picture must be a URL') })
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await wrapper.get('#user-profile').trigger('submit')
    await flushPromises()
    expect(writes(calls)).toHaveLength(0)
    await wrapper.get('#user-picture').setValue('nope')
    await wrapper.get('#user-profile').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('picture must be a URL')
    wrapper.unmount()
  })

  it('reports a missing user and a failing load', async () => {
    const missing = await mountAt(Detail, path, () => apiError(404, 'inexistent_user', 'The user does not exist.'))
    expect(missing.wrapper.text()).toContain('There is nothing at this address.')
    missing.wrapper.unmount()
    const failing = await mountAt(Detail, path, () => apiError(500, 'internal_error', 'Internal error'))
    expect(failing.wrapper.text()).toContain('Internal error')
    failing.wrapper.unmount()
  })

  it('shows blocked users with a tag', async () => {
    const { handler } = world({ user: user({ blocked: true }) })
    const { wrapper } = await mountAt(Detail, path, handler)
    expect(wrapper.get('h1').text()).toContain('Ada Lovelace')
    expect(wrapper.text()).toContain('Blocked')
    wrapper.unmount()
  })
})

describe('metadata tab', () => {
  it('blocks the save on invalid JSON, and on JSON that is not an object', async () => {
    const { handler } = world()
    const { calls, wrapper } = await mountAt(Detail, path, handler)
    await tab('Metadata')
    setInput(q<HTMLTextAreaElement>('#user-metadata-user'), '{ "theme": ')
    await flushPromises()
    await click(button('Review changes'))
    expect(q('#user-metadata-user-error').textContent).toContain('not valid JSON')
    expect(button('Save changes')).toBeUndefined()
    setInput(q<HTMLTextAreaElement>('#user-metadata-user'), '[1]')
    await click(button('Review changes'))
    expect(q('#user-metadata-user-error').textContent).toContain('JSON object')
    expect(writes(calls)).toHaveLength(0)
    wrapper.unmount()
  })

  it('removes a deleted key with null, replaces nested objects whole, and shows the diff first', async () => {
    const { handler } = world()
    const { calls, wrapper } = await mountAt(Detail, path, handler)
    await tab('Metadata')
    setInput(q<HTMLTextAreaElement>('#user-metadata-user'), JSON.stringify({ theme: 'dark', prefs: { b: 2 }, extra: true }))
    await flushPromises()
    await click(button('Review changes'))
    const diff = q('[data-testid="diff-user"]').textContent!
    expect(diff).toContain('color')
    expect(diff).toContain('Removed')
    expect(diff).toContain('extra')
    expect(diff).toContain('Added')
    expect(diff).toContain('prefs')
    expect(diff).toContain('Changed')
    expect(diff).not.toContain('theme')
    expect(writes(calls)).toHaveLength(0)
    await click(button('Save changes'))
    expect(writes(calls)).toHaveLength(1)
    expect(writes(calls)[0]!.body).toEqual({ user_metadata: { color: null, prefs: { b: 2 }, extra: true } })
    expect(wrapper.text()).toContain('Saved')
    wrapper.unmount()
  })

  it('says when nothing changed, and saves app_metadata alone', async () => {
    const { handler } = world()
    const { calls, wrapper } = await mountAt(Detail, path, handler)
    await tab('Metadata')
    await click(button('Review changes'))
    expect(q('[data-testid="diff-user"]').textContent).toContain('No changes')
    expect(button('Save changes')).toBeUndefined()
    setInput(q<HTMLTextAreaElement>('#user-metadata-app'), '{}')
    await flushPromises()
    const reviews = Array.from(body().querySelectorAll('button')).filter((b) => b.textContent?.trim() === 'Review changes')
    await click(reviews[0]!)
    await click(button('Save changes'))
    expect(writes(calls)[0]!.body).toEqual({ app_metadata: { plan: null } })
    wrapper.unmount()
  })

  it('turns app_metadata read-only when the caller lacks the scope', async () => {
    const { handler } = world({
      patch: () => apiError(403, 'insufficient_scope', 'Insufficient scope, expected any of: update:users_app_metadata'),
    })
    const { wrapper } = await mountAt(Detail, path, handler)
    await tab('Metadata')
    setInput(q<HTMLTextAreaElement>('#user-metadata-app'), '{"plan":"free"}')
    await flushPromises()
    const reviews = Array.from(body().querySelectorAll('button')).filter((b) => b.textContent?.trim() === 'Review changes')
    await click(reviews[1]!)
    await click(button('Save changes'))
    expect(wrapper.text()).toContain('cannot change app_metadata')
    expect(q<HTMLTextAreaElement>('#user-metadata-app').readOnly).toBe(true)
    expect(q<HTMLTextAreaElement>('#user-metadata-app').value).toContain('pro')
    expect(Array.from(body().querySelectorAll('button')).filter((b) => b.textContent?.trim() === 'Review changes')).toHaveLength(1)
    wrapper.unmount()
  })
})

describe('identities tab', () => {
  it('lists the identities and has no unlink for the main one', async () => {
    const { handler } = world()
    const { wrapper } = await mountAt(Detail, path, handler)
    await tab('Identities')
    expect(wrapper.text()).toContain('Users c0')
    expect(wrapper.text()).toContain('Main')
    expect(button('Unlink')).toBeUndefined()
    wrapper.unmount()
  })

  it('searches for a user to link, asks first, and links', async () => {
    const other = { user_id: 'auth0|zed', email: 'zed@example.test', identities: [{ connection: 'Users c0', user_id: 'zed', provider: 'auth0', isSocial: false }] } as User
    const { handler } = world({ search: [user(), other, { user_id: 'google-oauth2|9', email: 'g@example.test' } as User] })
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await tab('Identities')
    setInput(q<HTMLInputElement>('#link-search'), 'email:"zed@example.test"')
    await click(button('Search'))
    const search = calls.filter((c) => new URL(c.url).pathname === '/api/v2/users').at(-1)!
    expect(new URL(search.url).searchParams.get('q')).toBe('email:"zed@example.test"')
    expect(new URL(search.url).searchParams.get('search_engine')).toBe('v3')
    expect(q('[data-testid="link-results"]').textContent).toContain('zed@example.test')
    expect(q('[data-testid="link-results"]').textContent).not.toContain('g@example.test')
    expect(q('[data-testid="link-results"]').textContent).not.toContain('ada@example.test')
    await click(button('Link'))
    expect(writes(calls)).toHaveLength(0)
    expect(body().textContent).toContain('stops existing')
    await click(Array.from(body().querySelectorAll('[role="dialog"] button')).find((b) => b.textContent?.trim() === 'Link user')!)
    expect(writes(calls)[0]!.body).toEqual({ provider: 'auth0', user_id: 'zed' })
    expect(new URL(writes(calls)[0]!.url).pathname).toBe('/api/v2/users/auth0%7Cabc/identities')
    expect(wrapper.text()).toContain('zed@example.test')
    wrapper.unmount()
  })

  it('says when the search finds no one to link', async () => {
    const { handler } = world({ search: [] })
    const { wrapper } = await mountAt(Detail, path, handler)
    await tab('Identities')
    setInput(q<HTMLInputElement>('#link-search'), 'nobody')
    await click(button('Search'))
    expect(body().textContent).toContain('No database user matches')
    wrapper.unmount()
  })

  it('shows a search error', async () => {
    const { handler } = world({ fail: { 'GET /api/v2/users': apiError(400, 'invalid_query_string', 'Invalid search query') } })
    const { wrapper } = await mountAt(Detail, path, handler)
    await tab('Identities')
    setInput(q<HTMLInputElement>('#link-search'), 'a:(')
    await click(button('Search'))
    expect(body().textContent).toContain('Invalid search query')
    wrapper.unmount()
  })

  it('unlinks a linked identity after confirming', async () => {
    const linked = { connection: 'Users c0', user_id: 'zed', provider: 'auth0', isSocial: false, profileData: { email: 'zed@example.test' } }
    const { handler } = world({ user: user({ identities: [user().identities![0]!, linked] }) })
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await tab('Identities')
    await click(button('Unlink'))
    expect(writes(calls)).toHaveLength(0)
    await click(Array.from(body().querySelectorAll('[role="dialog"] button')).find((b) => b.textContent?.trim() === 'Unlink identity')!)
    expect(writes(calls)[0]!.method).toBe('DELETE')
    expect(decodeURIComponent(new URL(writes(calls)[0]!.url).pathname)).toBe('/api/v2/users/auth0|abc/identities/auth0/zed')
    expect(wrapper.text()).not.toContain('zed@example.test')
    wrapper.unmount()
  })
})

describe('sessions tab', () => {
  it('shows a loading state, then empty lists', async () => {
    const g = gated(world().handler, '/sessions')
    const { wrapper } = await mountAt(Detail, path, g.handler)
    tabTo('Sessions and devices')
    await flushPromises()
    expect(body().textContent).toContain('Loading')
    g.release()
    await flushPromises()
    expect(body().textContent).toContain('No active sessions.')
    expect(body().textContent).toContain('No refresh tokens.')
    wrapper.unmount()
  })

  it('shows an error with a retry for each list', async () => {
    const { handler, w } = world({ fail: { 'GET /api/v2/users/auth0|abc/sessions': apiError(403, 'insufficient_scope', 'Insufficient scope, expected any of: read:sessions') } })
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await tab('Sessions and devices')
    expect(body().textContent).toContain('read:sessions')
    delete w.fail
    const before = calls.length
    await click(button('Try again'))
    expect(calls.length).toBeGreaterThan(before)
    expect(body().textContent).toContain('No active sessions.')
    wrapper.unmount()
  })

  it('lists sessions and tokens, revokes one, and revokes all after confirming', async () => {
    const { handler } = world({ sessions: [session('s1'), session('s2')], tokens: [token('t1')] })
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await tab('Sessions and devices')
    expect(body().textContent).toContain('Firefox')
    expect(body().textContent).toContain('10.0.0.2')
    expect(body().textContent).toContain('cli1')
    expect(body().textContent).toContain('https://api.test/')
    const first = new URL(calls.find((c) => c.url.includes('/sessions'))!.url)
    expect(first.searchParams.get('take')).toBe('50')
    await click(body().querySelector('[aria-label="Revoke session s1"]')!)
    expect(writes(calls).at(-1)!.method).toBe('DELETE')
    expect(new URL(writes(calls).at(-1)!.url).pathname).toBe('/api/v2/sessions/s1')
    expect(body().querySelector('[aria-label="Revoke session s1"]')).toBeNull()
    expect(body().querySelector('[aria-label="Revoke session s2"]')).not.toBeNull()
    await click(body().querySelector('[aria-label="Revoke refresh token t1"]')!)
    expect(new URL(writes(calls).at(-1)!.url).pathname).toBe('/api/v2/refresh-tokens/t1')
    await click(button('Revoke all sessions'))
    const n = writes(calls).length
    await click(Array.from(body().querySelectorAll('[role="dialog"] button')).find((b) => b.textContent?.trim() === 'Revoke all')!)
    expect(writes(calls).length).toBe(n + 1)
    expect(new URL(writes(calls).at(-1)!.url).pathname).toBe('/api/v2/users/auth0%7Cabc/sessions')
    expect(body().textContent).toContain('No active sessions.')
    wrapper.unmount()
  })

  it('pages sessions with the cursor', async () => {
    const all = Array.from({ length: 51 }, (_, i) => session('s' + i))
    const { handler } = world({ sessions: all })
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await tab('Sessions and devices')
    expect(body().querySelector('[aria-label="Revoke session s49"]')).not.toBeNull()
    expect(body().querySelector('[aria-label="Revoke session s50"]')).toBeNull()
    await click(button('Show more sessions'))
    expect(new URL(calls.filter((c) => c.url.includes('/sessions')).at(-1)!.url).searchParams.get('from')).toBe('50')
    expect(body().querySelector('[aria-label="Revoke session s50"]')).not.toBeNull()
    expect(button('Show more sessions')).toBeUndefined()
    wrapper.unmount()
  })
})

describe('applications tab', () => {
  it('shows loading, empty, error and success states', async () => {
    const g = gated(world().handler, '/grants')
    const a = await mountAt(Detail, path, g.handler)
    tabTo('Authorized applications')
    await flushPromises()
    expect(body().textContent).toContain('Loading')
    g.release()
    await flushPromises()
    expect(body().textContent).toContain('has not authorized any application')
    a.wrapper.unmount()

    const failing = world({ fail: { 'GET /api/v2/grants': apiError(403, 'insufficient_scope', 'Insufficient scope, expected any of: read:grants') } })
    const b = await mountAt(Detail, path, failing.handler)
    await tab('Authorized applications')
    expect(body().textContent).toContain('read:grants')
    b.wrapper.unmount()

    const ok = world({ grants: [grant('g1')] })
    const c = await mountAt(Detail, path, ok.handler)
    await tab('Authorized applications')
    expect(new URL(c.calls.find((x) => x.url.includes('/grants'))!.url).searchParams.get('user_id')).toBe('auth0|abc')
    expect(body().textContent).toContain('cli1')
    expect(body().textContent).toContain('read write')
    await click(body().querySelector('[aria-label="Revoke access for cli1 to https://api.test/"]')!)
    expect(new URL(writes(c.calls).at(-1)!.url).pathname).toBe('/api/v2/grants/g1')
    expect(body().textContent).toContain('has not authorized any application')
    c.wrapper.unmount()
  })
})

describe('raw tab', () => {
  it('shows the user as JSON', async () => {
    const { handler } = world()
    const { wrapper } = await mountAt(Detail, path, handler)
    await tab('Raw JSON')
    const text = body().querySelector('pre')!.textContent!
    expect(JSON.parse(text).email).toBe('ada@example.test')
    expect(text.toLowerCase()).not.toContain('password')
    wrapper.unmount()
  })
})

describe('actions', () => {
  it('blocks and unblocks', async () => {
    const { handler } = world()
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await click(button('Block'))
    await click(Array.from(body().querySelectorAll('[role="dialog"] button')).find((b) => b.textContent?.trim() === 'Block user')!)
    expect(writes(calls)[0]!.body).toEqual({ blocked: true })
    expect(wrapper.text()).toContain('Blocked')
    await click(button('Unblock'))
    expect(writes(calls)[1]!.body).toEqual({ blocked: false })
    wrapper.unmount()
  })

  it('changes the password and the email, one per request', async () => {
    const { handler } = world()
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await click(button('Change password'))
    setInput(q<HTMLInputElement>('#action-password'), 'a-very-long-new-passphrase')
    await click(button('Set password'))
    expect(writes(calls)[0]!.body).toEqual({ password: 'a-very-long-new-passphrase' })
    expect(body().querySelector('#action-password')).toBeNull()
    await click(button('Change email'))
    setInput(q<HTMLInputElement>('#action-email'), 'new@example.test')
    await click(button('Set email'))
    expect(writes(calls)[1]!.body).toEqual({ email: 'new@example.test' })
    expect(wrapper.text()).toContain('new@example.test')
    wrapper.unmount()
  })

  it('shows a password refusal from the server', async () => {
    const { handler } = world({ patch: () => apiError(400, '', 'PasswordStrengthError: Password is too weak') })
    const { wrapper } = await mountAt(Detail, path, handler)
    await click(button('Change password'))
    setInput(q<HTMLInputElement>('#action-password'), 'x')
    await click(button('Set password'))
    expect(body().textContent).toContain('Password is too weak')
    wrapper.unmount()
  })

  it('shows the password link once, with its lifetime, and keeps it out of the store', async () => {
    const { handler } = world()
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await click(button('Create password link'))
    expect(writes(calls)[0]!.body).toEqual({ user_id: 'auth0|abc' })
    expect(q('[data-testid="ticket-url"]').textContent).toBe('https://acme.example.test/lo/reset?ticket=SECRETRESET')
    expect(body().textContent).toContain('5 days')
    expect(body().textContent).toContain('shown only once')
    expect(button('Copy')).toBeDefined()
    expect(JSON.stringify(getActivePinia()!.state.value)).not.toContain('SECRET')
    // Close it: the URL is gone from the page and cannot be shown again.
    await click(button('Done', q('[role="dialog"]')))
    expect(body().textContent).not.toContain('SECRETRESET')
    expect(wrapper.html()).not.toContain('SECRETRESET')
    expect(JSON.stringify(getActivePinia()!.state.value)).not.toContain('SECRET')
    wrapper.unmount()
  })

  it('queues the verification email job and shows its id', async () => {
    const { handler } = world()
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await click(button('Send verification email'))
    const sent = writes(calls)
    expect(sent).toHaveLength(1)
    expect(new URL(sent[0]!.url).host).toBe('acme.example.test')
    expect(new URL(sent[0]!.url).pathname).toBe('/api/v2/jobs/verification-email')
    expect(sent[0]!.body).toEqual({ user_id: 'auth0|abc' })
    expect(q('[role="status"]').textContent).toContain('job_abcdefgh12345678')
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    wrapper.unmount()
  })

  it('shows why the verification job was refused', async () => {
    const { handler } = world({ fail: { 'POST /api/v2/jobs/verification-email': apiError(400, 'operation_not_supported', 'The user has no email address') } })
    const { wrapper } = await mountAt(Detail, path, handler)
    await click(button('Send verification email'))
    expect(q('[role="alert"]').textContent).toContain('The user has no email address')
    expect(document.body.textContent).not.toContain('queued')
    wrapper.unmount()
  })

  it('still offers the verification link to copy', async () => {
    const { handler } = world()
    const { wrapper, calls } = await mountAt(Detail, path, handler)
    await click(button('Create verification link'))
    expect(new URL(writes(calls)[0]!.url).pathname).toBe('/api/v2/tickets/email-verification')
    expect(q('[data-testid="ticket-url"]').textContent).toContain('SECRETVERIFY')
    wrapper.unmount()
  })

  it('keeps delete disabled until the email is typed, and lists what goes with the user', async () => {
    const { handler } = world()
    const { wrapper, calls, router } = await mountAt(Detail, path, handler)
    await click(button('Delete user'))
    const dialog = q('[role="dialog"]')
    for (const w of ['sessions', 'refresh tokens', 'grants', 'tickets']) expect(dialog.textContent).toContain(w)
    const del = Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Delete user')!
    expect(del.disabled).toBe(true)
    setInput(q<HTMLInputElement>('#delete-confirm'), 'ada@example')
    await flushPromises()
    expect(del.disabled).toBe(true)
    setInput(q<HTMLInputElement>('#delete-confirm'), 'ada@example.test')
    await flushPromises()
    expect(del.disabled).toBe(false)
    await click(del)
    expect(writes(calls)[0]!.method).toBe('DELETE')
    expect(router.currentRoute.value.name).toBe('users')
    wrapper.unmount()
  })

  it('asks for the user ID when there is no email', async () => {
    const { handler } = world({ user: user({ email: undefined }) })
    const { wrapper } = await mountAt(Detail, path, handler)
    await click(button('Delete user'))
    const del = Array.from(q('[role="dialog"]').querySelectorAll('button')).find((b) => b.textContent?.trim() === 'Delete user')!
    setInput(q<HTMLInputElement>('#delete-confirm'), 'auth0|abc')
    await flushPromises()
    expect(del.disabled).toBe(false)
    wrapper.unmount()
  })
})
