import { describe, expect, it, vi } from 'vitest'
import { reactive } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { installGuards, routes } from './router'

function fakes(authenticated: boolean) {
  const auth = { user: reactive({ authenticated, email: '', sub: '' }), login: vi.fn(async () => undefined) }
  const tenants = { state: reactive({ list: [], loaded: false, error: '' }), load: vi.fn(async () => undefined) }
  return { auth, tenants }
}

function router(f: ReturnType<typeof fakes>) {
  const r = createRouter({ history: createMemoryHistory('/admin/'), routes })
  installGuards(r, f as never)
  return r
}

describe('router guards', () => {
  it('signs an unauthenticated operator in, returning to the deep link', async () => {
    const f = fakes(false)
    const r = router(f)
    await r.push('/t/acme/applications/abc?x=1')
    expect(f.auth.login).toHaveBeenCalledWith('/t/acme/applications/abc?x=1', true)
    expect(r.currentRoute.value.name).not.toBe('application')
    expect(f.tenants.load).not.toHaveBeenCalled()
  })

  it('lets the callback through without a session', async () => {
    const f = fakes(false)
    const r = router(f)
    await r.push('/callback?code=c&state=s')
    expect(r.currentRoute.value.name).toBe('callback')
    expect(f.auth.login).not.toHaveBeenCalled()
  })

  it('loads the tenants once for a signed-in operator', async () => {
    const f = fakes(true)
    f.tenants.load.mockImplementation(async () => void (f.tenants.state.loaded = true))
    const r = router(f)
    await r.push('/t/acme/')
    expect(r.currentRoute.value.name).toBe('home')
    await r.push('/t/acme/applications')
    expect(r.currentRoute.value.name).toBe('applications')
    expect(f.tenants.load).toHaveBeenCalledTimes(1)
    expect(f.auth.login).not.toHaveBeenCalled()
  })

  it('names the routes of a deep link', async () => {
    const f = fakes(true)
    f.tenants.state.loaded = true
    const r = router(f)
    await r.push('/t/acme/applications/new')
    expect(r.currentRoute.value.name).toBe('application-new')
    await r.push('/t/acme/applications/xyz')
    expect(r.currentRoute.value.name).toBe('application')
    expect(r.currentRoute.value.params.id).toBe('xyz')
    await r.push('/t/acme/connections')
    expect(r.currentRoute.value.name).toBe('connections')
    await r.push('/t/acme/connections/new')
    expect(r.currentRoute.value.name).toBe('connection-new')
    await r.push('/t/acme/connections/con_abc')
    expect(r.currentRoute.value.name).toBe('connection')
    expect(r.currentRoute.value.params.id).toBe('con_abc')
    await r.push('/nowhere')
    expect(r.currentRoute.value.name).toBe('not-found')
  })
})
