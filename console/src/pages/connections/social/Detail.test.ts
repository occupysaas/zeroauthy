import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { connection, type Call } from '../../../test/services'
import Detail from './Detail.vue'
import List from './List.vue'

const oauth = connection('con_o', {
  name: 'prov', strategy: 'oauth2', realms: ['prov'],
  options: { client_id: 'cid', authorizationURL: 'https://p.example/a', tokenURL: 'https://p.example/t', scope: 'read', scripts: { fetchUserProfile: 'function fetchUserProfile(a,c,cb){}' } },
})

function route(handler: (c: Call) => unknown) {
  return (c: Call) => {
    const path = new URL(c.url).pathname
    if (path.endsWith('/clients')) return { status: 200, body: { clients: [], start: 0, limit: 100, total: 0 } }
    return handler(c) as never
  }
}

describe('Social connection detail', () => {
  it('shows immutable fields read-only, never a secret, and saves options whole', async () => {
    const saved = { ...oauth, options: { ...oauth.options, scope: 'read write' } }
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/social/con_o', route((c) => (c.method === 'PATCH' ? { status: 200, body: saved } : { status: 200, body: oauth })))
    expect(wrapper.find<HTMLInputElement>('#social-client-id').element.readOnly).toBe(true)
    expect(wrapper.find<HTMLInputElement>('#social-token').element.readOnly).toBe(true)
    expect(wrapper.find<HTMLTextAreaElement>('#social-script').element.readOnly).toBe(true)
    expect(wrapper.find<HTMLInputElement>('#social-secret').element.value).toBe('')
    await wrapper.find('#social-scope').setValue('read write')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const patch = calls.find((c) => c.method === 'PATCH')!
    const body = patch.body as { options: Record<string, unknown>; authentication: unknown }
    expect(body.options).toEqual({ ...oauth.options, scope: 'read write' }) // no client_secret: the stored one is kept
    expect(body.authentication).toEqual({ active: true })
    expect(wrapper.text()).toContain('Saved.')
    wrapper.unmount()
  })

  it('sends a replacement secret only when one is typed, then clears it', async () => {
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/social/con_o', route(() => ({ status: 200, body: oauth })))
    await wrapper.find('#social-secret').setValue('rotated')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect((calls.find((c) => c.method === 'PATCH')!.body as { options: Record<string, unknown> }).options.client_secret).toBe('rotated')
    expect(wrapper.find<HTMLInputElement>('#social-secret').element.value).toBe('')
    wrapper.unmount()
  })

  it('keeps edits after an uncertain save', async () => {
    const { wrapper } = await mountAt(Detail, '/t/acme/social/con_o', route((c) => {
      if (c.method === 'PATCH') throw new TypeError('network down')
      return { status: 200, body: oauth }
    }))
    await wrapper.find('#social-scope').setValue('edited')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('may have been saved')
    expect(wrapper.find<HTMLInputElement>('#social-scope').element.value).toBe('edited')
    wrapper.unmount()
  })

  it('labels the OIDC subset and offers the applications tab', async () => {
    const oidc = connection('con_i', { name: 'corp', strategy: 'oidc', options: { client_id: 'c', discovery_url: 'https://i.example/d', scopes: 'openid' } })
    const { wrapper } = await mountAt(Detail, '/t/acme/social/con_i', route(() => ({ status: 200, body: oidc })))
    expect(wrapper.find('[data-testid="oidc-subset"]').exists()).toBe(true)
    expect(wrapper.findAll('[role="tab"]').map((t) => t.text())).toEqual(['Settings', 'Applications', 'Danger zone'])
    expect(wrapper.text()).not.toContain('Password')
    wrapper.unmount()
  })

  it('does not open a database connection here', async () => {
    const { wrapper } = await mountAt(Detail, '/t/acme/social/con_db', route(() => ({ status: 200, body: connection('con_db') })))
    expect(wrapper.find('form').exists()).toBe(false)
    wrapper.unmount()
  })

  it('ignores a stale reply after navigating to another connection', async () => {
    let release: (v: unknown) => void = () => {}
    const slow = new Promise((r) => (release = r))
    const other = { ...oauth, id: 'con_2', name: 'second' }
    const { wrapper, router } = await mountAt(Detail, '/t/acme/social/con_o', route(async (c) => {
      if (c.url.endsWith('/con_o')) {
        await slow
        return { status: 200, body: oauth }
      }
      return { status: 200, body: other }
    }))
    await router.push('/t/acme/social/con_2')
    await flushPromises()
    release(undefined)
    await flushPromises()
    expect(wrapper.find('h1').text()).toBe('second')
    wrapper.unmount()
  })
})

describe('Social connection list', () => {
  it('lists only federated connections', async () => {
    const page = { connections: [connection('con_db'), oauth, connection('con_g', { name: 'goog', strategy: 'google-oauth2' })], start: 0, limit: 100, total: 3 }
    const { wrapper } = await mountAt(List, '/t/acme/social', () => ({ status: 200, body: page }))
    expect(wrapper.findAll('tbody tr').map((r) => r.text())).toEqual(['provCustom OAuth 2', 'googGoogle'])
    wrapper.unmount()
  })
})
