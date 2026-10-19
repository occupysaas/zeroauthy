import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Connection } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import { client, connection, type Call, type Reply } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/connections/con_1'
const body = () => document.body

function tabTo(name: string) {
  const trigger = Array.from(body().querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}
function button(label: string, root: ParentNode = body()): HTMLButtonElement {
  return Array.from(root.querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
}
function setInput(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  el.value = value
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input'))
}
function check(el: HTMLInputElement, on: boolean) {
  el.checked = on
  el.dispatchEvent(new Event('change'))
}
const q = <T extends Element = HTMLElement>(sel: string) => body().querySelector<T>(sel)!

type Opts = Record<string, Record<string, unknown> & Record<string, string>>
const BLOB = 'zcv1.AAAAsealedblobA'
const BLOB_B = 'zcv1.BBBBsealedblobB'

function withScripts(): Connection {
  const c = connection('con_1', { name: 'People' })
  Object.assign(c.options!, {
    enabledDatabaseCustomization: true,
    customScripts: { login: 'function login(email, password, cb) { cb(null, {}) }', get_user: 'function getUser(email, cb) { cb(null, null) }' },
    configuration: { API_KEY: BLOB, DB_URL: BLOB_B },
  })
  return c
}

// A small tenant: one connection, a few applications, the script runner.
function backend(opts: { conn?: Connection; enabled?: string[]; tryReply?: Reply } = {}) {
  const state = { conn: opts.conn ?? connection('con_1', { name: 'People' }), enabled: opts.enabled ?? ['a1'] }
  const handler = (c: Call): Reply => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections/con_1') {
      if (c.method === 'PATCH') {
        const patch = c.body as Partial<Connection>
        state.conn = { ...state.conn, ...patch }
        return { status: 200, body: state.conn }
      }
      if (c.method === 'DELETE') return { status: 202, body: { deleted_at: '2026-10-18T00:00:00Z' } }
      return { status: 200, body: state.conn }
    }
    if (u.pathname === '/api/v2/connections/con_1/clients') {
      if (c.method === 'PATCH') {
        for (const e of c.body as { client_id: string; status: boolean }[]) {
          state.enabled = e.status ? [...state.enabled, e.client_id] : state.enabled.filter((x) => x !== e.client_id)
        }
        return { status: 204 }
      }
      return { status: 200, body: { clients: state.enabled.map((client_id) => ({ client_id })) } }
    }
    if (u.pathname === '/api/v2/clients') {
      const clients = [client('a1', { name: 'Web' }), client('a2', { name: 'Mobile' })]
      return { status: 200, body: { clients, start: 0, limit: 100, total: 2 } }
    }
    if (u.pathname.endsWith('/try')) return opts.tryReply ?? { status: 200, body: { result: { user_id: 'u1' }, error: null, logs: ['hello'], duration_ms: 12 } }
    return { status: 404 }
  }
  return { state, handler }
}

const patches = (calls: Call[]) => calls.filter((c) => c.method === 'PATCH' && new URL(c.url).pathname === '/api/v2/connections/con_1')

describe('connection detail', () => {
  afterEach(() => {
    document.body.innerHTML = ''
    vi.restoreAllMocks()
  })

  it('shows loading, then the connection with its tabs', async () => {
    const pending = await mountAt(Detail, path, () => new Promise(() => undefined))
    expect(pending.wrapper.find('[role="status"]').text()).toBe('Loading…')
    pending.wrapper.unmount()

    const b = backend()
    const { wrapper } = await mountAt(Detail, path, b.handler)
    expect(wrapper.find('h1').text()).toBe('People')
    expect(Array.from(body().querySelectorAll('[role="tab"]')).map((x) => x.textContent?.trim())).toEqual([
      'Settings',
      'Password policy',
      'Custom database',
      'Applications',
      'Danger zone',
    ])
    wrapper.unmount()
  })

  it('reports not found, and an error with a retry', async () => {
    const nf = await mountAt(Detail, path, () => apiError(404, 'inexistent_connection', 'No such connection'))
    expect(nf.wrapper.text()).toContain('There is nothing at this address.')
    nf.wrapper.unmount()

    let fail = true
    const b = backend()
    const { wrapper } = await mountAt(Detail, path, (c) => (fail ? apiError(500, 'internal_error', 'Internal error') : b.handler(c)))
    expect(wrapper.find('[role="alert"]').text()).toContain('Internal error')
    fail = false
    await wrapper.findAll('button').find((x) => x.text() === 'Try again')!.trigger('click')
    await flushPromises()
    expect(wrapper.find('h1').text()).toBe('People')
    wrapper.unmount()
  })

  it('shows the seed banner on a seeded tenant', async () => {
    const { wrapper } = await mountAt(Detail, path, backend().handler, { seeded: true })
    expect(wrapper.text()).toContain('The seed file defines this tenant')
    wrapper.unmount()
  })

  describe('settings', () => {
    it('marks every stored-not-enforced setting and shows unknown options read-only', async () => {
      const { wrapper } = await mountAt(Detail, path, backend().handler)
      const stored = q('[data-testid="stored-group"]')
      expect(stored.textContent).toContain('Saved, not enforced yet')
      for (const label of ['Display name', 'Show as a button', 'Realms', 'Metadata', 'Connected accounts', 'Authentication', 'Authentication methods', 'Passkey options', 'Attributes', 'Identifier precedence', 'Multi-factor authentication', 'Disable self-service password change', 'Non-persistent attributes']) {
        const row = Array.from(stored.querySelectorAll('label')).find((l) => l.textContent?.includes(label))
        expect(row?.querySelector('[data-testid="not-enforced"]'), label).toBeTruthy()
      }
      const unknown = q('[data-testid="unknown-json"]')
      expect(unknown.tagName).toBe('PRE')
      expect(JSON.parse(unknown.textContent!)).toEqual({ strategy_version: 2, acme_custom_flag: { keep: ['me'] } })
      expect(q('[data-testid="unknown-group"]').querySelector('input, textarea')).toBeNull()
      wrapper.unmount()
    })

    it('sends the complete merged options when one setting changes', async () => {
      const b = backend()
      const original = JSON.parse(JSON.stringify(b.state.conn.options))
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      check(q<HTMLInputElement>('input[type="checkbox"]'), false) // brute force
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      const sent = patches(calls)
      expect(sent).toHaveLength(1)
      expect(sent[0]!.body).toEqual({ options: { ...original, brute_force_protection: false } })
      expect(body().textContent).toContain('Saved')
      wrapper.unmount()
    })

    it('sends only the stored settings that changed, top-level ones beside options', async () => {
      const b = backend()
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      setInput(q<HTMLInputElement>('#stored-display_name'), 'People database')
      setInput(q<HTMLTextAreaElement>('#stored-metadata'), '{"team":"core"}')
      setInput(q<HTMLTextAreaElement>('#stored-precedence'), 'email\nusername\nphone_number')
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      const sent = patches(calls)[0]!.body as { options: Record<string, unknown>; display_name: string; metadata: unknown; realms?: unknown }
      expect(sent.display_name).toBe('People database')
      expect(sent.metadata).toEqual({ team: 'core' })
      expect(sent.realms).toBeUndefined()
      expect(sent.options.precedence).toEqual(['email', 'username', 'phone_number'])
      expect(sent.options.acme_custom_flag).toEqual({ keep: ['me'] })
      expect(sent.options.mfa).toEqual({ active: true, return_enroll_settings: true })
      wrapper.unmount()
    })

    it('validates before calling the API', async () => {
      const { wrapper, calls } = await mountAt(Detail, path, backend().handler)
      setInput(q<HTMLInputElement>('#conn-username-min'), '0')
      setInput(q<HTMLInputElement>('#conn-username-max'), '200')
      setInput(q<HTMLTextAreaElement>('#stored-mfa'), '[1]')
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(q('#conn-username-min-error').textContent).toContain('at least 1')
      expect(q('#conn-username-max-error').textContent).toContain('at most 128')
      expect(body().textContent).toContain('Enter a JSON object')
      setInput(q<HTMLInputElement>('#conn-username-min'), '10')
      setInput(q<HTMLInputElement>('#conn-username-max'), '5')
      setInput(q<HTMLTextAreaElement>('#stored-mfa'), '')
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(q('#conn-username-max-error').textContent).toContain('greater than the shortest')
      expect(patches(calls)).toHaveLength(0)
      wrapper.unmount()
    })

    it('shows a server refusal', async () => {
      const b = backend()
      const { wrapper } = await mountAt(Detail, path, (c) => (c.method === 'PATCH' ? apiError(400, 'invalid_body', 'Payload validation error: nope') : b.handler(c)))
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(body().querySelector('[role="alert"]')!.textContent).toContain('nope')
      wrapper.unmount()
    })
  })

  describe('password policy', () => {
    it('changes one part and sends the whole options, password_options included', async () => {
      const b = backend({ conn: withScripts() })
      const original = JSON.parse(JSON.stringify(b.state.conn.options))
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Password policy')
      await flushPromises()
      setInput(q<HTMLInputElement>('#pw-min'), '12')
      check(q<HTMLInputElement>('input[value="number"]'), true)
      setInput(q<HTMLSelectElement>('#pw-identical'), 'block')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      const sent = patches(calls)[0]!.body as { options: Opts }
      expect(Object.keys(sent.options).sort()).toEqual(Object.keys(original).sort())
      expect(sent.options.password_options.complexity).toMatchObject({ min_length: 12, character_types: ['number'], identical_characters: 'block', sequential_characters: 'allow' })
      expect(sent.options.password_options.history).toEqual({ active: false, size: 3 })
      expect(sent.options.password_options.profile_data).toEqual({ active: false, blocked_fields: ['name', 'email'] })
      expect(sent.options.configuration).toEqual({ API_KEY: BLOB, DB_URL: BLOB_B })
      expect(sent.options.customScripts).toEqual(original.customScripts)
      expect(sent.options.acme_custom_flag).toEqual({ keep: ['me'] })
      wrapper.unmount()
    })

    it('refuses invalid values without calling the API', async () => {
      const { wrapper, calls } = await mountAt(Detail, path, backend().handler)
      tabTo('Password policy')
      await flushPromises()
      setInput(q<HTMLInputElement>('#pw-min'), '73')
      setInput(q<HTMLSelectElement>('#pw-rule'), 'three_of_four')
      setInput(q<HTMLInputElement>('#pw-history-size'), '25')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().textContent).toContain('whole number from 1 to 72')
      expect(body().textContent).toContain('needs all four character types')
      expect(body().textContent).toContain('whole number from 1 to 24')
      expect(patches(calls)).toHaveLength(0)
      wrapper.unmount()
    })

    it('runs the live checker from the unsaved form, in the browser only', async () => {
      const setItem = vi.spyOn(Storage.prototype, 'setItem')
      const { wrapper, calls } = await mountAt(Detail, path, backend().handler)
      tabTo('Password policy')
      await flushPromises()
      const state = (id: string) => q(`[data-testid="rule-${id}"]`).dataset.state
      setInput(q<HTMLInputElement>('#pw-sample'), 'abc')
      await flushPromises()
      expect(state('length')).toBe('fail') // 15 characters by default
      expect(state('identical')).toBe('off')
      setInput(q<HTMLSelectElement>('#pw-identical'), 'block')
      setInput(q<HTMLInputElement>('#pw-min'), '3')
      setInput(q<HTMLInputElement>('#pw-sample'), 'aaab')
      await flushPromises()
      expect(state('length')).toBe('pass')
      expect(state('identical')).toBe('fail')
      check(q<HTMLInputElement>('input[type="checkbox"][value="special"]'), true)
      await flushPromises()
      expect(state('types')).toBe('fail')
      expect(q('[data-testid="rule-history"]').textContent).toContain('Server only')
      expect(q('[data-testid="rule-common"]').textContent).toContain('Server only')
      expect(q('[data-testid="checker"]').textContent).toContain('checked by the server only')
      // The sample password went nowhere.
      expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0)
      expect(JSON.stringify(calls)).not.toContain('aaab')
      expect(setItem).not.toHaveBeenCalled()
      wrapper.unmount()
    })

    it('checks personal data and your own words from the form', async () => {
      const { wrapper } = await mountAt(Detail, path, backend().handler)
      tabTo('Password policy')
      await flushPromises()
      check(q<HTMLInputElement>('#pw-dict-active'), true)
      setInput(q<HTMLTextAreaElement>('#pw-dict-custom'), 'Hunter2')
      setInput(q<HTMLInputElement>('#pw-sample'), 'hunter2')
      await flushPromises()
      expect(q('[data-testid="rule-dictionary"]').dataset.state).toBe('fail')
      check(q<HTMLInputElement>('#pw-profile-active'), true)
      setInput(q<HTMLInputElement>('#pw-profile-name'), 'Jordan Lee')
      setInput(q<HTMLInputElement>('#pw-sample'), 'x-jordan lee-x')
      await flushPromises()
      expect(q('[data-testid="rule-personal"]').dataset.state).toBe('fail')
      wrapper.unmount()
    })
  })

  describe('custom database', () => {
    it('never renders configuration values, only masked keys with a replace action', async () => {
      const { wrapper } = await mountAt(Detail, path, backend({ conn: withScripts() }).handler)
      tabTo('Custom database')
      await flushPromises()
      const html = body().innerHTML
      expect(html).not.toContain(BLOB)
      expect(html).not.toContain(BLOB_B)
      const row = q('[data-testid="config-API_KEY"]')
      expect(row.textContent).toContain('API_KEY')
      expect(row.textContent).toContain('••••••••')
      expect(button('Replace', row)).toBeTruthy()
      expect(Array.from(body().querySelectorAll<HTMLInputElement>('input')).every((i) => !i.value.includes('zcv1'))).toBe(true)
      wrapper.unmount()
    })

    it('after a save the response blobs are still never rendered, and an edit elsewhere keeps them', async () => {
      const b = backend({ conn: withScripts() })
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Custom database')
      await flushPromises()
      setInput(q<HTMLTextAreaElement>('#script-src-get_user'), 'function getUser(email, cb) { cb(null, {}) }')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().innerHTML).not.toContain('zcv1')
      const first = patches(calls)[0]!.body as { options: Opts }
      expect(first.options.configuration).toEqual({ API_KEY: BLOB, DB_URL: BLOB_B })
      expect(first.options.customScripts.get_user).toContain('cb(null, {})')
      expect(first.options.customScripts.login).toContain('function login')
      expect(first.options.password_options).toEqual((b.state.conn.options as Opts).password_options)
      // Then an edit on another tab keeps the scripts and the configuration.
      tabTo('Settings')
      await flushPromises()
      check(q<HTMLInputElement>('input[type="checkbox"]'), false)
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      const second = patches(calls)[1]!.body as { options: Opts }
      expect(second.options.configuration).toEqual({ API_KEY: BLOB, DB_URL: BLOB_B })
      expect(second.options.customScripts.get_user).toContain('cb(null, {})')
      expect(second.options.enabledDatabaseCustomization).toBe(true)
      expect(second.options.brute_force_protection).toBe(false)
      wrapper.unmount()
    })

    it('replaces, removes and adds configuration keys; only edited keys carry plaintext', async () => {
      const b = backend({ conn: withScripts() })
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Custom database')
      await flushPromises()
      button('Replace', q('[data-testid="config-API_KEY"]')).click()
      await flushPromises()
      setInput(q<HTMLInputElement>('input[aria-label="New value for API_KEY"]'), 'fresh-secret')
      button('Remove', q('[data-testid="config-DB_URL"]')).click()
      await flushPromises()
      button('Add a value').click()
      await flushPromises()
      setInput(q<HTMLInputElement>('input[aria-label="Key"]'), 'TOKEN')
      setInput(q<HTMLInputElement>('input[aria-label="Value"]'), 'tok')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      const sent = patches(calls)[0]!.body as { options: Opts }
      expect(sent.options.configuration).toEqual({ API_KEY: 'fresh-secret', TOKEN: 'tok' })
      // The typed plaintext is not on the page after the save either.
      expect(body().innerHTML).not.toContain('fresh-secret')
      expect(Array.from(body().querySelectorAll<HTMLInputElement>('input')).some((i) => i.value === 'fresh-secret')).toBe(false)
      wrapper.unmount()
    })

    it('sends the new value of a key that was removed and added again', async () => {
      const b = backend({ conn: withScripts() })
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Custom database')
      await flushPromises()
      button('Remove', q('[data-testid="config-DB_URL"]')).click()
      await flushPromises()
      button('Add a value').click()
      await flushPromises()
      setInput(q<HTMLInputElement>('input[aria-label="Key"]'), 'DB_URL')
      setInput(q<HTMLInputElement>('input[aria-label="Value"]'), 'postgres://new')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      const sent = patches(calls)[0]!.body as { options: Opts }
      expect(sent.options.configuration).toEqual({ API_KEY: BLOB, DB_URL: 'postgres://new' })
      wrapper.unmount()
    })

    it('keeps the stored value of a key whose replacement was left empty', async () => {
      const b = backend({ conn: withScripts() })
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Custom database')
      await flushPromises()
      button('Replace', q('[data-testid="config-API_KEY"]')).click()
      await flushPromises()
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      const sent = patches(calls)[0]!.body as { options: Opts }
      expect(sent.options.configuration).toEqual({ API_KEY: BLOB, DB_URL: BLOB_B })
      wrapper.unmount()
    })

    it('validates configuration keys', async () => {
      const { wrapper, calls } = await mountAt(Detail, path, backend({ conn: withScripts() }).handler)
      tabTo('Custom database')
      await flushPromises()
      button('Add a value').click()
      await flushPromises()
      setInput(q<HTMLInputElement>('input[aria-label="Key"]'), 'bad key')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().textContent).toContain('1 to 128 letters, digits or underscores')
      setInput(q<HTMLInputElement>('input[aria-label="Key"]'), 'API_KEY')
      await q<HTMLFormElement>('form').dispatchEvent(new Event('submit'))
      await flushPromises()
      expect(body().textContent).toContain('already used')
      expect(patches(calls)).toHaveLength(0)
      wrapper.unmount()
    })

    it('has a script editor with line numbers', async () => {
      const { wrapper } = await mountAt(Detail, path, backend({ conn: withScripts() }).handler)
      tabTo('Custom database')
      await flushPromises()
      const ed = q('[data-testid="script-login"]')
      expect(ed.querySelector('textarea')).toBeTruthy()
      setInput(ed.querySelector('textarea')!, 'a\nb\nc')
      await flushPromises()
      expect(ed.querySelectorAll('[data-testid="gutter"] div')).toHaveLength(3)
      wrapper.unmount()
    })

    describe('try', () => {
      async function open(reply?: Reply) {
        const b = backend({ conn: withScripts(), tryReply: reply })
        const m = await mountAt(Detail, path, b.handler)
        tabTo('Custom database')
        await flushPromises()
        return m
      }
      const run = async () => {
        button('Try', q('[data-testid="try-login"]')).click()
        await flushPromises()
      }

      it('shows the result, the console output and the note, and calls the system API', async () => {
        const setItem = vi.spyOn(Storage.prototype, 'setItem')
        const { wrapper, calls } = await open()
        await run()
        const call = calls.find((c) => c.url.endsWith('/try'))!
        expect(call.method).toBe('POST')
        expect(call.url).toBe('https://admin.example.test/api/system/tenants/acme/connections/con_1/scripts/login/try')
        expect(call.body).toEqual({ args: ['user@example.com', 'a-test-password'] })
        const out = q('[data-testid="try-login"] [data-testid="try-result"]')
        expect(out.textContent).toContain('u1')
        expect(out.textContent).toContain('hello')
        expect(out.textContent).toContain('12 ms')
        expect(out.textContent).toContain('replaced with ■■■■■■■■')
        expect(setItem).not.toHaveBeenCalled()
        expect(sessionStorage.length).toBe(0)
        wrapper.unmount()
        expect(body().textContent).not.toContain('u1')
      })

      it('shows a script error', async () => {
        const { wrapper } = await open({ status: 200, body: { result: null, error: { name: 'WrongUsernameOrPasswordError', message: 'nope' }, logs: [], duration_ms: 3 } })
        await run()
        const out = q('[data-testid="try-result"]')
        expect(out.textContent).toContain('WrongUsernameOrPasswordError')
        expect(out.textContent).toContain('nope')
        wrapper.unmount()
      })

      it('shows a timeout', async () => {
        const { wrapper } = await open({ status: 200, body: { result: null, error: { name: 'TimeoutError', message: 'ran too long' }, logs: [], duration_ms: 20000 } })
        await run()
        expect(q('[data-testid="try-result"]').textContent).toContain('ran too long and was stopped')
        wrapper.unmount()
      })

      it('shows the rate limit with the wait', async () => {
        const { wrapper } = await open({ status: 429, headers: { 'Retry-After': '42' }, body: { statusCode: 429, error: 'Too Many Requests', errorCode: 'too_many_requests', message: 'Slow down' } })
        await run()
        expect(q('[data-testid="try-login"]').textContent).toContain('Wait 42 seconds')
        expect(q('[data-testid="try-login"] [role="alert"]')).toBeTruthy()
        wrapper.unmount()
      })

      it('shows an unavailable runtime and a server error, and refuses bad arguments', async () => {
        const rt = await open(apiError(503, 'script_runtime_unavailable', 'no node'))
        await run()
        expect(q('[data-testid="try-login"]').textContent).toContain('runtime is not available')
        rt.wrapper.unmount()
        document.body.innerHTML = ''
        const bad = await open()
        setInput(q<HTMLTextAreaElement>('#try-args-login'), 'not json')
        await run()
        expect(q('[data-testid="try-login"]').textContent).toContain('Enter a JSON array')
        expect(bad.calls.some((c) => c.url.endsWith('/try'))).toBe(false)
        bad.wrapper.unmount()
      })
    })
  })

  describe('applications', () => {
    it('switches an application through the clients endpoint, never enabled_clients', async () => {
      const b = backend()
      const { wrapper, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Applications')
      await flushPromises()
      const web = q<HTMLInputElement>('input[aria-label="Enable this connection for Web"]')
      const mobile = q<HTMLInputElement>('input[aria-label="Enable this connection for Mobile"]')
      expect(web.checked).toBe(true)
      expect(mobile.checked).toBe(false)
      check(mobile, true)
      await flushPromises()
      check(web, false)
      await flushPromises()
      const sent = calls.filter((c) => c.method === 'PATCH')
      expect(sent.map((c) => new URL(c.url).pathname)).toEqual(['/api/v2/connections/con_1/clients', '/api/v2/connections/con_1/clients'])
      expect(sent.map((c) => c.body)).toEqual([[{ client_id: 'a2', status: true }], [{ client_id: 'a1', status: false }]])
      expect(JSON.stringify(sent)).not.toContain('enabled_clients')
      wrapper.unmount()
    })

    it('shows a row error and lists an error and empty state', async () => {
      const b = backend()
      const { wrapper } = await mountAt(Detail, path, (c) => (c.method === 'PATCH' ? apiError(400, 'inexistent_client', 'No such app') : b.handler(c)))
      tabTo('Applications')
      await flushPromises()
      check(q<HTMLInputElement>('input[aria-label="Enable this connection for Mobile"]'), true)
      await flushPromises()
      expect(q('[data-testid="app-a2"]').textContent).toContain('No such app')
      wrapper.unmount()
      document.body.innerHTML = ''
      const empty = await mountAt(Detail, path, (c) => (new URL(c.url).pathname === '/api/v2/clients' ? { status: 200, body: { clients: [], start: 0, limit: 100, total: 0 } } : b.handler(c)))
      tabTo('Applications')
      await flushPromises()
      expect(body().textContent).toContain('no applications yet')
      empty.wrapper.unmount()
    })
  })

  describe('danger zone', () => {
    it('asks for the typed name, says the users go too, and deletes', async () => {
      const b = backend()
      const { wrapper, router, calls } = await mountAt(Detail, path, b.handler)
      tabTo('Danger zone')
      await flushPromises()
      expect(body().textContent).toContain('all users of this connection')
      button('Delete connection').click()
      await flushPromises()
      expect(body().textContent).toContain('All users of this connection are deleted with it')
      const submit = Array.from(body().querySelectorAll<HTMLButtonElement>('button[type="submit"]')).find((x) => x.textContent?.trim() === 'Delete connection')!
      expect(submit.disabled).toBe(true)
      setInput(q<HTMLInputElement>('#delete-confirm'), 'people')
      await flushPromises()
      expect(submit.disabled).toBe(true)
      setInput(q<HTMLInputElement>('#delete-confirm'), 'People')
      await flushPromises()
      expect(submit.disabled).toBe(false)
      submit.click()
      await flushPromises()
      expect(calls.some((c) => c.method === 'DELETE' && c.url.endsWith('/api/v2/connections/con_1'))).toBe(true)
      expect(router.currentRoute.value.path).toBe('/t/acme/connections')
      wrapper.unmount()
    })

    it('shows a failed delete', async () => {
      const b = backend()
      const { wrapper, router } = await mountAt(Detail, path, (c) => (c.method === 'DELETE' ? apiError(500, 'internal_error', 'Could not delete') : b.handler(c)))
      tabTo('Danger zone')
      await flushPromises()
      button('Delete connection').click()
      await flushPromises()
      setInput(q<HTMLInputElement>('#delete-confirm'), 'People')
      await flushPromises()
      Array.from(body().querySelectorAll<HTMLButtonElement>('button[type="submit"]')).find((x) => x.textContent?.trim() === 'Delete connection')!.click()
      await flushPromises()
      expect(body().textContent).toContain('Could not delete')
      expect(router.currentRoute.value.path).toBe(path)
      wrapper.unmount()
    })
  })
})
