import { describe, expect, it, vi } from 'vitest'
import { Auth, CLIENT_ID, TXN_KEY } from './auth'
import { base64url, challengeFor } from './pkce'

const origin = 'https://admin.example.test'

function memoryStorage() {
  const m = new Map<string, string>()
  return {
    m,
    getItem: (k: string) => m.get(k) ?? null,
    setItem: vi.fn((k: string, v: string) => void m.set(k, v)),
    removeItem: (k: string) => void m.delete(k),
  }
}

function jwt(payload: object): string {
  const enc = (o: object) => base64url(new TextEncoder().encode(JSON.stringify(o)))
  return enc({ alg: 'RS256' }) + '.' + enc(payload) + '.sig'
}

function json(status: number, body: object): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function setup() {
  const responses: Response[] = []
  const storage = memoryStorage()
  const navigate = vi.fn<(url: string) => void>()
  const calls: { url: string; body: URLSearchParams }[] = []
  const fetchFn = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(url), body: new URLSearchParams(String(init?.body ?? '')) })
    const next = responses.shift()
    if (!next) throw new Error('unexpected fetch ' + String(url))
    return next
  })
  let now = 1_000_000
  const auth = new Auth({ origin }, { fetch: fetchFn as typeof fetch, navigate, storage, now: () => now })
  return { auth, storage, navigate, calls, responses, advance: (ms: number) => (now += ms) }
}

async function signIn(s: ReturnType<typeof setup>, tokens: object) {
  await s.auth.login('/t/acme/applications', true)
  const authorize = new URL(s.navigate.mock.calls.at(-1)![0])
  const txn = JSON.parse(s.storage.m.get(TXN_KEY)!)
  return { authorize, txn, tokens: { id_token: jwt({ nonce: txn.nonce, email: 'op@example.test', sub: 'auth0|op' }), ...tokens } }
}

describe('Auth', () => {
  it('starts a PKCE sign-in with S256, state and nonce', async () => {
    const s = setup()
    const { authorize, txn } = await signIn(s, {})
    expect(authorize.origin + authorize.pathname).toBe(origin + '/authorize')
    const q = authorize.searchParams
    expect(q.get('client_id')).toBe(CLIENT_ID)
    expect(q.get('response_type')).toBe('code')
    expect(q.get('redirect_uri')).toBe(origin + '/admin/callback')
    expect(q.get('audience')).toBe('urn:zeroauthy:management')
    expect(q.get('scope')).toContain('offline_access')
    expect(q.get('code_challenge_method')).toBe('S256')
    expect(q.get('code_challenge')).toBe(await challengeFor(txn.verifier))
    expect(txn.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(q.get('state')).toBe(txn.state)
    expect(q.get('nonce')).toBe(txn.nonce)
    expect(q.get('prompt')).toBe('none')
  })

  it('exchanges the code and keeps the tokens out of storage', async () => {
    const s = setup()
    const { txn, tokens } = await signIn(s, {})
    s.responses.push(json(200, { access_token: 'AT-1', refresh_token: 'RT-1', expires_in: 3600, ...tokens }))
    const next = await s.auth.handleCallback(`?code=CODE&state=${txn.state}`)
    expect(next).toBe('/t/acme/applications')
    const body = s.calls[0]!.body
    expect(s.calls[0]!.url).toBe(origin + '/oauth/token')
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('code_verifier')).toBe(txn.verifier)
    expect(body.get('client_id')).toBe(CLIENT_ID)
    expect(s.auth.user.authenticated).toBe(true)
    expect(s.auth.user.email).toBe('op@example.test')
    expect(await s.auth.accessToken()).toBe('AT-1')
    // The transaction is gone and no token was ever written.
    expect(s.storage.m.size).toBe(0)
    for (const [, v] of s.storage.setItem.mock.calls) {
      expect(v).not.toContain('AT-1')
      expect(v).not.toContain('RT-1')
    }
  })

  it('refuses a response for another sign-in', async () => {
    const s = setup()
    await signIn(s, {})
    await expect(s.auth.handleCallback('?code=CODE&state=forged')).rejects.toMatchObject({ code: 'invalid_state' })
    expect(s.auth.user.authenticated).toBe(false)
  })

  it('falls back to an interactive sign-in when the silent one fails', async () => {
    const s = setup()
    const { txn } = await signIn(s, {})
    const next = await s.auth.handleCallback(`?error=login_required&state=${txn.state}`)
    expect(next).toBeNull()
    const again = new URL(s.navigate.mock.calls.at(-1)![0])
    expect(again.searchParams.get('prompt')).toBeNull()
    expect(JSON.parse(s.storage.m.get(TXN_KEY)!).returnTo).toBe('/t/acme/applications')
  })

  it('reports an interactive failure', async () => {
    const s = setup()
    await s.auth.login('/', false)
    const txn = JSON.parse(s.storage.m.get(TXN_KEY)!)
    await expect(s.auth.handleCallback(`?error=access_denied&error_description=no&state=${txn.state}`)).rejects.toMatchObject({
      code: 'access_denied',
    })
  })

  it('refreshes before expiry with the rotating refresh token', async () => {
    const s = setup()
    const { txn, tokens } = await signIn(s, {})
    s.responses.push(
      json(200, { access_token: 'AT-1', refresh_token: 'RT-1', expires_in: 120, ...tokens }),
      json(200, { access_token: 'AT-2', refresh_token: 'RT-2', expires_in: 120 }),
      json(200, { access_token: 'AT-3', refresh_token: 'RT-3', expires_in: 120 }),
    )
    await s.auth.handleCallback(`?code=CODE&state=${txn.state}`)
    expect(await s.auth.accessToken()).toBe('AT-1')
    s.advance(61_000) // within a minute of expiry
    const [a, b] = await Promise.all([s.auth.accessToken(), s.auth.accessToken()])
    expect([a, b]).toEqual(['AT-2', 'AT-2'])
    const refreshes = s.calls.filter((c) => c.body.get('grant_type') === 'refresh_token')
    expect(refreshes).toHaveLength(1)
    expect(refreshes[0]!.body.get('refresh_token')).toBe('RT-1')
    s.advance(61_000)
    expect(await s.auth.accessToken()).toBe('AT-3')
    expect(s.calls.at(-1)!.body.get('refresh_token')).toBe('RT-2')
  })

  it('forgets the session when the refresh fails', async () => {
    const s = setup()
    const { txn, tokens } = await signIn(s, {})
    s.responses.push(
      json(200, { access_token: 'AT-1', refresh_token: 'RT-1', expires_in: 30, ...tokens }),
      json(400, { error: 'invalid_grant', error_description: 'gone' }),
    )
    await s.auth.handleCallback(`?code=CODE&state=${txn.state}`)
    await expect(s.auth.accessToken()).rejects.toMatchObject({ code: 'invalid_grant' })
    expect(s.auth.user.authenticated).toBe(false)
  })
})
