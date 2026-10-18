import { describe, expect, it } from 'vitest'
import { authorizeURL, callCurl, expressConfig, nextjsEnv, shQuote, spaJS, spaReact, tokenCurl, type AppFacts } from './snippets'

const facts = (host: string, extra: Partial<AppFacts> = {}): AppFacts => ({
  host,
  clientID: 'cid123',
  authMethod: 'client_secret_post',
  callbacks: [],
  ...extra,
})

describe('snippets', () => {
  it('quotes for the shell', () => {
    expect(shQuote("it's")).toBe(`'it'\\''s'`)
  })

  it.each([
    ['a host without a port', 'acme.example.test', 'https://acme.example.test/oauth/token'],
    ['a host with a port', 'acme.localtest.me:8443', 'https://acme.localtest.me:8443/oauth/token'],
    ['a custom domain with no base domain', 'login.acme.test', 'https://login.acme.test/oauth/token'],
  ])('writes the token curl for %s', (_n, host, url) => {
    const c = tokenCurl(facts(host), 'https://api.test/orders', 'sec')
    expect(c).toBe(
      [
        `curl --request POST --url '${url}'`,
        `  --header 'content-type: application/x-www-form-urlencoded'`,
        `  --data grant_type=client_credentials`,
        `  --data-urlencode 'client_id=cid123'`,
        `  --data-urlencode 'client_secret=sec'`,
        `  --data-urlencode 'audience=https://api.test/orders'`,
      ].join(' \\\n'),
    )
  })

  it('uses a placeholder until the secret is given, and quotes odd secrets and audiences', () => {
    expect(tokenCurl(facts('h.test'), 'a', null)).toContain(`client_secret=YOUR_CLIENT_SECRET'`)
    const c = tokenCurl(facts('h.test'), "urn:x'y&z=1", "se'cret")
    expect(c).toContain(`'client_secret=se'\\''cret'`)
    expect(c).toContain(`'audience=urn:x'\\''y&z=1'`)
  })

  it('follows the application’s token endpoint authentication', () => {
    expect(tokenCurl(facts('h.test', { authMethod: 'client_secret_basic' }), 'a', 's')).toContain(`--user 'cid123:s'`)
    const pub = tokenCurl(facts('h.test', { authMethod: 'none' }), 'a', null)
    expect(pub).not.toContain('client_secret')
    expect(pub).toContain('client_id=cid123')
  })

  it('calls the API with the token', () => {
    expect(callCurl('https://api.test/orders')).toBe(`curl --url 'https://api.test/orders' \\\n  --header 'authorization: Bearer ACCESS_TOKEN'`)
  })

  it.each([
    ['acme.example.test', 'https://acme.example.test/authorize?'],
    ['acme.localtest.me:8443', 'https://acme.localtest.me:8443/authorize?'],
  ])('writes the authorize URL for %s', (host, prefix) => {
    const u = authorizeURL(facts(host, { callbacks: ['http://localhost:3000/cb?x=1'] }))
    expect(u.startsWith(prefix)).toBe(true)
    const q = new URL(u).searchParams
    expect(q.get('client_id')).toBe('cid123')
    expect(q.get('redirect_uri')).toBe('http://localhost:3000/cb?x=1')
    expect(q.get('response_type')).toBe('code')
    expect(q.get('code_challenge_method')).toBe('S256')
    expect(q.get('scope')).toBe('openid profile email')
  })

  it('configures the single-page SDKs with the host as the domain', () => {
    const f = facts('acme.localtest.me:8443', { callbacks: ['https://app.test/cb'] })
    for (const s of [spaJS(f), spaReact(f)]) {
      expect(s).toContain(`'acme.localtest.me:8443'`)
      expect(s).toContain(`'cid123'`)
      expect(s).toContain(`redirect_uri: 'https://app.test/cb'`)
      expect(s).toContain('audience:')
    }
    expect(spaReact(f)).toContain('authorizationParams={{')
  })

  it('configures the web SDKs, with the secret only when given', () => {
    const f = facts('acme.example.test')
    expect(nextjsEnv(f, null)).toContain('AUTH0_DOMAIN=acme.example.test')
    expect(nextjsEnv(f, null)).toContain('AUTH0_CLIENT_SECRET=YOUR_CLIENT_SECRET')
    expect(nextjsEnv(f, 'sec')).toContain('AUTH0_CLIENT_SECRET=sec')
    expect(expressConfig(f, 'sec')).toContain(`issuerBaseURL: 'https://acme.example.test'`)
    expect(expressConfig(f, null)).not.toContain('sec\'')
  })
})
