import { reactive } from 'vue'
import { challengeFor, claims, randomString } from './pkce'

// The console signs in to the system tenant with the authorization code
// flow and PKCE. Tokens live in memory only; the rotating refresh token
// too. A reload signs in again silently (prompt=none) through the
// system tenant's session.

export const CLIENT_ID = 'zeroauthy-console'
export const AUDIENCE = 'urn:zeroauthy:management'
export const SCOPE = 'openid profile email offline_access'

// TXN_KEY holds the in-flight sign-in (state, verifier, nonce, where to
// return), never a token.
export const TXN_KEY = 'zeroauthy.console.signin'

// Refresh this long before the access token expires.
const EARLY_MS = 60_000

export interface AuthConfig {
  // origin is the system host's origin; the issuer is origin + '/'.
  origin: string
}

export interface AuthDeps {
  fetch: typeof fetch
  navigate: (url: string) => void
  storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
  now: () => number
}

interface Txn {
  state: string
  verifier: string
  nonce: string
  returnTo: string
  silent: boolean
}

interface Tokens {
  access: string
  refresh?: string
  expiresAt: number
}

export class SignInError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message)
  }
}

const silentFailures = ['login_required', 'consent_required', 'interaction_required']

export class Auth {
  readonly user = reactive({ authenticated: false, email: '', sub: '' })
  private tokens: Tokens | null = null
  private refreshing: Promise<string> | null = null
  private deps: AuthDeps

  constructor(
    private cfg: AuthConfig,
    deps?: Partial<AuthDeps>,
  ) {
    this.deps = {
      fetch: (...a) => window.fetch(...a),
      navigate: (url) => window.location.assign(url),
      storage: window.sessionStorage,
      now: () => Date.now(),
      ...deps,
    }
  }

  get redirectURI(): string {
    return this.cfg.origin + '/admin/callback'
  }

  // login sends the browser to /authorize. silent tries the existing
  // session first (prompt=none); handleCallback falls back to an
  // interactive sign-in when it fails.
  async login(returnTo: string, silent = true): Promise<void> {
    const txn: Txn = { state: randomString(), verifier: randomString(), nonce: randomString(), returnTo, silent }
    this.deps.storage.setItem(TXN_KEY, JSON.stringify(txn))
    const q = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: this.redirectURI,
      scope: SCOPE,
      audience: AUDIENCE,
      state: txn.state,
      nonce: txn.nonce,
      code_challenge: await challengeFor(txn.verifier),
      code_challenge_method: 'S256',
    })
    if (silent) q.set('prompt', 'none')
    this.deps.navigate(this.cfg.origin + '/authorize?' + q.toString())
  }

  // handleCallback finishes a sign-in from the callback's query string and
  // returns where to go next, or null when it started another sign-in.
  async handleCallback(search: string): Promise<string | null> {
    const p = new URLSearchParams(search)
    const raw = this.deps.storage.getItem(TXN_KEY)
    this.deps.storage.removeItem(TXN_KEY)
    const txn = raw ? (JSON.parse(raw) as Txn) : null
    if (!txn || p.get('state') !== txn.state) {
      throw new SignInError('invalid_state', 'The sign-in response does not match a sign-in this browser started.')
    }
    const error = p.get('error')
    if (error) {
      if (txn.silent && silentFailures.includes(error)) {
        await this.login(txn.returnTo, false)
        return null
      }
      throw new SignInError(error, p.get('error_description') ?? error)
    }
    const body = await this.token({
      grant_type: 'authorization_code',
      code: p.get('code') ?? '',
      redirect_uri: this.redirectURI,
      code_verifier: txn.verifier,
    })
    const id = typeof body.id_token === 'string' ? claims(body.id_token) : {}
    if (id.nonce !== txn.nonce) {
      throw new SignInError('invalid_nonce', 'The ID token does not belong to this sign-in.')
    }
    this.user.email = typeof id.email === 'string' ? id.email : ''
    this.user.sub = typeof id.sub === 'string' ? id.sub : ''
    this.user.authenticated = true
    return txn.returnTo
  }

  // accessToken returns a token valid for at least another minute,
  // refreshing it first when needed.
  async accessToken(): Promise<string> {
    const t = this.tokens
    if (!t) throw new SignInError('login_required', 'Not signed in.')
    if (t.expiresAt - EARLY_MS > this.deps.now()) return t.access
    if (!t.refresh) {
      this.reset()
      throw new SignInError('login_required', 'The session expired.')
    }
    this.refreshing ??= this.token({ grant_type: 'refresh_token', refresh_token: t.refresh })
      .then(() => this.tokens!.access)
      .catch((err) => {
        this.reset()
        throw err
      })
      .finally(() => {
        this.refreshing = null
      })
    return this.refreshing
  }

  // logout forgets the tokens and ends the system tenant's session.
  logout(): void {
    const refresh = this.tokens?.refresh
    this.reset()
    if (refresh) {
      // Best effort; the session ends at /v2/logout either way.
      void this.post('/oauth/revoke', { client_id: CLIENT_ID, token: refresh }).catch(() => undefined)
    }
    const q = new URLSearchParams({ client_id: CLIENT_ID, returnTo: this.cfg.origin + '/admin/' })
    this.deps.navigate(this.cfg.origin + '/v2/logout?' + q.toString())
  }

  private reset(): void {
    this.tokens = null
    this.user.authenticated = false
    this.user.email = ''
    this.user.sub = ''
  }

  private async post(path: string, form: Record<string, string>): Promise<Response> {
    return this.deps.fetch(this.cfg.origin + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
      // Lets the revocation at sign-out finish while the page unloads.
      keepalive: true,
    })
  }

  private async token(form: Record<string, string>): Promise<Record<string, unknown>> {
    const res = await this.post('/oauth/token', { client_id: CLIENT_ID, ...form })
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
    if (!res.ok || typeof body.access_token !== 'string') {
      const code = typeof body.error === 'string' ? body.error : 'token_error'
      const desc = typeof body.error_description === 'string' ? body.error_description : 'The token request failed.'
      throw new SignInError(code, desc)
    }
    const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 0
    this.tokens = {
      access: body.access_token,
      // A rotating refresh token: keep the newest.
      refresh: typeof body.refresh_token === 'string' ? body.refresh_token : this.tokens?.refresh,
      expiresAt: this.deps.now() + expiresIn * 1000,
    }
    return body
  }
}
