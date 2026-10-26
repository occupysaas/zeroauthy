import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountAt } from '../../test/mount'
import DomainDetail from './DomainDetail.vue'
import { domain } from './fixtures'

afterEach(() => { document.body.innerHTML = ''; localStorage.clear(); sessionStorage.clear() })

const selfManaged = domain({ type: 'self_managed_certs' })

describe('the one-time proxy key', () => {
  it('is shown once, never stored, and gone after navigation', async () => {
    let verified = false
    const { wrapper, router, calls } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', c => {
      if (c.url.endsWith('/verify')) {
        verified = true
        return { status: 200, body: { ...selfManaged, status: 'ready', cname_api_key: 'secret-proxy-key' } }
      }
      return { status: 200, body: { ...selfManaged, status: verified ? 'ready' : 'pending_verification' } }
    })
    await wrapper.findAll('button').find(b => b.text().includes('Verify now'))!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('secret-proxy-key')
    expect(wrapper.find('[role=dialog], [aria-live]').exists()).toBe(true)
    expect(JSON.stringify({ ...localStorage })).not.toContain('secret-proxy-key')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('secret-proxy-key')
    expect(router.currentRoute.value.fullPath).not.toContain('secret')
    await wrapper.findAll('button').find(b => b.text().includes('I have stored the key'))!.trigger('click')
    expect(wrapper.text()).not.toContain('secret-proxy-key')
    await router.push('/t/acme/custom-domains')
    await router.push('/t/acme/custom-domains/cd_1')
    await flushPromises()
    expect(wrapper.text()).not.toContain('secret-proxy-key')
    expect(calls.filter(c => c.url.endsWith('/verify'))).toHaveLength(1)
  })

  it('does not retry an uncertain verify; it refreshes the status instead', async () => {
    const { wrapper, calls } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', c => {
      if (c.url.endsWith('/verify')) return { status: 503, body: { statusCode: 503, errorCode: 'temporarily_unavailable', message: 'unavailable' } }
      return { status: 200, body: selfManaged }
    })
    const gets = calls.filter(c => c.method === 'GET').length
    await wrapper.findAll('button').find(b => b.text().includes('Verify now'))!.trigger('click')
    await flushPromises()
    expect(calls.filter(c => c.url.endsWith('/verify'))).toHaveLength(1)
    expect(calls.filter(c => c.method === 'GET').length).toBeGreaterThan(gets)
    expect(wrapper.text()).toContain('cannot be shown again')
    expect((wrapper.find('form button[type=submit]').element as HTMLButtonElement).disabled).toBe(false)
  })

  it('reports rate limits without retrying', async () => {
    const { wrapper, calls } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', c => {
      if (c.url.endsWith('/verify')) return { status: 429, body: { statusCode: 429, errorCode: 'too_many_requests', message: 'Too many' }, headers: { 'Retry-After': '17' } }
      return { status: 200, body: selfManaged }
    })
    await wrapper.findAll('button').find(b => b.text().includes('Verify now'))!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Try again in 17 seconds')
    expect(calls.filter(c => c.url.endsWith('/verify'))).toHaveLength(1)
  })
})
