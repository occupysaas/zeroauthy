import { createPinia, setActivePinia } from 'pinia'
import { reactive } from 'vue'
import { beforeEach, describe, expect, it } from 'vitest'
import { fakeServices, tenant } from '../test/services'
import { usePreferencesStore } from './preferences'
import { useSessionStore } from './session'
import { useTenantsStore } from './tenants'

beforeEach(() => {
  setActivePinia(createPinia())
  window.localStorage.clear()
  delete document.documentElement.dataset.theme
})

describe('tenants store', () => {
  it('load stores the list and marks it loaded', async () => {
    const { services } = fakeServices(() => ({ status: 200, body: [tenant('acme')] }))
    const s = useTenantsStore()
    await s.load(services.api)
    expect(s.list.map((t) => t.name)).toEqual(['acme'])
    expect(s.loaded).toBe(true)
    expect(s.error).toBe('')
  })

  it('load keeps the error text on a 500 and still marks loaded', async () => {
    const { services } = fakeServices(() => ({ status: 500, body: { statusCode: 500, error: 'Error', errorCode: 'server_error', message: 'boom' } }))
    const s = useTenantsStore()
    await s.load(services.api)
    expect(s.error).toBe('boom')
    expect(s.loaded).toBe(true)
  })

  it('create inserts in name order', async () => {
    const { services } = fakeServices(() => ({ status: 201, body: tenant('c') }))
    const s = useTenantsStore()
    s.list = [tenant('b'), tenant('d')]
    await s.create(services.api, { name: 'c' })
    expect(s.list.map((t) => t.name)).toEqual(['b', 'c', 'd'])
  })

  it('first is the first non-reserved tenant, else the system tenant', () => {
    const s = useTenantsStore()
    s.list = [tenant('system', { reserved: true }), tenant('acme')]
    expect(s.first()?.name).toBe('acme')
    s.list = [tenant('system', { reserved: true })]
    expect(s.first()?.name).toBe('system')
    expect(s.find('system')?.reserved).toBe(true)
  })
})

describe('preferences store', () => {
  it('setTheme applies and remembers the theme', () => {
    const p = usePreferencesStore()
    p.setTheme('dark')
    expect(p.theme).toBe('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(window.localStorage.getItem('zeroauthy.console.theme')).toBe('dark')
  })

  it('setLocale stores the locale', () => {
    const p = usePreferencesStore()
    p.setLocale('en')
    expect(p.locale).toBe('en')
  })
})

describe('session store', () => {
  it('follows the attached user', () => {
    const user = reactive({ authenticated: true, email: 'a@b.test', sub: 'auth0|a' })
    const s = useSessionStore()
    s.attach(user)
    user.email = 'x@y.test'
    expect(s.email).toBe('x@y.test')
    expect(s.sub).toBe('auth0|a')
    expect(s.authenticated).toBe(true)
  })
})
