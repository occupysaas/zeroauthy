import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { client, connection, type Call } from '../../../test/services'
import Create from './Create.vue'
import list from './descriptors.json'
import { descriptorOf, descriptorOptions, descriptorScope, descriptorStrategies, descriptorFlagsOf, isSocialConnection, socialStrategies } from './social'

const apps = (c: Call) =>
  new URL(c.url).pathname === '/api/v2/clients' ? { status: 200, body: { clients: [client('a1', { name: 'Web' })], start: 0, limit: 100, total: 1 } } : undefined

async function open() {
  return mountAt(Create, '/t/acme/social/new', (c) => apps(c) ?? ({ status: 201, body: connection('con_new', { strategy: 'facebook' }) } as never))
}

describe('Plan 39b descriptor strategies', () => {
  it('lists exactly the generated descriptors, after the dedicated providers', () => {
    expect([...descriptorStrategies]).toEqual(list.map((d) => d.strategy))
    expect(socialStrategies.slice(0, 5)).toEqual(['google-oauth2', 'oauth2', 'windowslive', 'apple', 'github'])
    expect(socialStrategies.slice(5)).toEqual([...descriptorStrategies])
    expect(isSocialConnection({ strategy: 'facebook' })).toBe(true)
    expect(isSocialConnection({ strategy: 'oauth1' })).toBe(true)
  })

  it('derives the effective scope from base scopes, flags and freeform scopes', () => {
    const fb = descriptorOf('facebook')!
    const flags = descriptorFlagsOf(fb, {})
    expect(flags.public_profile).toBe(true)
    expect(descriptorScope(fb, { ...flags, email: true }, 'extra:read')).toBe('public_profile,email,extra:read')
    expect(descriptorScope(descriptorOf('twitter')!, descriptorFlagsOf(descriptorOf('twitter')!, {}), '', 'oauth1')).toBe('')
    expect(descriptorOptions(fb, { ...flags, email: true, public_profile: false }, ' a  b ', {})).toEqual({ public_profile: false, email: true, freeform_scopes: ['a', 'b'] })
  })
})

describe('Create a descriptor connection', () => {
  async function fill(wrapper: Awaited<ReturnType<typeof open>>['wrapper'], strategy: string) {
    await wrapper.find(`input[value="${strategy}"]`).setValue(true)
    await wrapper.find('#social-name').setValue(strategy)
    await wrapper.find('#social-client-id').setValue('client-1')
    await wrapper.find('#social-client-secret').setValue('fixture-secret')
  }

  it('sends the flags and freeform scopes, never scope, and shows the derived scope', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'facebook')
    expect(wrapper.find<HTMLInputElement>('#descriptor-effective').element.value).toBe('public_profile')
    await wrapper.find('#descriptor-flag-email').setValue(true)
    await wrapper.find('#descriptor-freeform').setValue('pages_read_engagement')
    expect(wrapper.find<HTMLInputElement>('#descriptor-effective').element.value).toBe('public_profile,email,pages_read_engagement')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ name: 'facebook', strategy: 'facebook', enabled_clients: [],
      options: { client_id: 'client-1', client_secret: 'fixture-secret', email: true, freeform_scopes: ['pages_read_engagement'] } })
    wrapper.unmount()
  })

  it('requires an https community URL for Salesforce Community', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'salesforce-community')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(wrapper.find('#descriptor-community-error').exists()).toBe(true)
    await wrapper.find('#descriptor-community').setValue('http://community.example.com')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    await wrapper.find('#descriptor-community').setValue('https://community.example.com')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect((calls.find((c) => c.method === 'POST')?.body as { options: Record<string, unknown> }).options.community_base_url).toBe('https://community.example.com')
    wrapper.unmount()
  })

  it('offers the Twitter protocol and hides scope flags for OAuth 1.0a', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'twitter')
    expect(wrapper.find('#descriptor-flag-tweet_read').exists()).toBe(true)
    await wrapper.find('#descriptor-protocol').setValue('oauth1')
    expect(wrapper.find('#descriptor-flag-tweet_read').exists()).toBe(false)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect((calls.find((c) => c.method === 'POST')?.body as { options: Record<string, unknown> }).options.protocol).toBe('oauth1')
    wrapper.unmount()
  })

  it('explains that Shopify needs the shop as login_hint', async () => {
    const { wrapper } = await open()
    await wrapper.find('input[value="shopify"]').setValue(true)
    expect(wrapper.find('[data-testid="descriptor-login-hint"]').exists()).toBe(true)
    wrapper.unmount()
  })
})

describe('Descriptor connection settings', () => {
  it('shows the stored flags and saves flags and freeform scopes, never scope', async () => {
    const { default: Detail } = await import('./Detail.vue')
    const fb = connection('con_fb', { name: 'facebook', strategy: 'facebook', options: { client_id: 'fb-app', email: true, scope: 'public_profile,email', freeform_scopes: ['x:read'] } })
    const { wrapper, calls } = await mountAt(Detail, '/t/acme/social/con_fb', (c) => {
      if (new URL(c.url).pathname.endsWith('/clients')) return { status: 200, body: { clients: [], start: 0, limit: 100, total: 0 } } as never
      return { status: 200, body: fb } as never
    })
    expect(wrapper.find<HTMLInputElement>('#descriptor-flag-email').element.checked).toBe(true)
    expect(wrapper.find<HTMLInputElement>('#descriptor-flag-public_profile').element.checked).toBe(true)
    expect(wrapper.find<HTMLInputElement>('#descriptor-effective').element.value).toBe('public_profile,email,x:read')
    await wrapper.find('#descriptor-flag-user_birthday').setValue(true)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    const body = calls.find((c) => c.method === 'PATCH')!.body as { options: Record<string, unknown> }
    expect(body.options).toEqual({ client_id: 'fb-app', email: true, user_birthday: true, freeform_scopes: ['x:read'] })
    wrapper.unmount()
  })
})

describe('Plan 39d Tier 2 descriptors', () => {
  async function fill(wrapper: Awaited<ReturnType<typeof open>>['wrapper'], strategy: string) {
    await wrapper.find(`input[value="${strategy}"]`).setValue(true)
    await wrapper.find('#social-name').setValue(strategy)
    await wrapper.find('#social-client-id').setValue('client-1')
    await wrapper.find('#social-client-secret').setValue('fixture-secret')
  }

  it('sends a typed free scope as an array and shows it as the effective scope', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'wordpress')
    expect(wrapper.find<HTMLInputElement>('#descriptor-effective').element.value).toBe('auth')
    await wrapper.find('#descriptor-scope').setValue('global auth')
    expect(wrapper.find<HTMLInputElement>('#descriptor-effective').element.value).toBe('global auth')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect((calls.find((c) => c.method === 'POST')?.body as { options: Record<string, unknown> }).options).toEqual({ client_id: 'client-1', client_secret: 'fixture-secret', scope: ['global', 'auth'] })
    wrapper.unmount()
  })

  it('refuses more than 20 free scopes', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'yandex')
    await wrapper.find('#descriptor-scope').setValue(Array.from({ length: 21 }, (_, i) => `s${i}`).join(' '))
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
    wrapper.unmount()
  })

  it('requires an Exact region and sends it as baseUrl', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'exact')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(wrapper.find('#descriptor-base-url-error').exists()).toBe(true)
    await wrapper.find('#descriptor-base-url').setValue('https://start.exactonline.be')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect((calls.find((c) => c.method === 'POST')?.body as { options: Record<string, unknown> }).options.baseUrl).toBe('https://start.exactonline.be')
    wrapper.unmount()
  })

  it('warns that Fitbit and Instagram sign-in is retired but still allows saving', async () => {
    const { wrapper } = await open()
    for (const s of ['fitbit', 'instagram']) {
      await wrapper.find(`input[value="${s}"]`).setValue(true)
      expect(wrapper.find('[data-testid="descriptor-retired"]').text()).toMatch(/retired|shut down|turned off/i)
    }
    wrapper.unmount()
  })

  it('creates Evernote with only the consumer key and secret', async () => {
    const { wrapper, calls } = await open()
    await fill(wrapper, 'evernote')
    expect(wrapper.find('#descriptor-scope').exists()).toBe(false)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect((calls.find((c) => c.method === 'POST')?.body as { options: Record<string, unknown> }).options).toEqual({ client_id: 'client-1', client_secret: 'fixture-secret' })
    wrapper.unmount()
  })
})
