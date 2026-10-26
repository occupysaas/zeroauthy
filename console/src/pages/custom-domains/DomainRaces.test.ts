import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountAt } from '../../test/mount'
import CustomDomains from './CustomDomains.vue'
import DomainDetail from './DomainDetail.vue'
import { domain } from './fixtures'

afterEach(() => { document.body.innerHTML = '' })

describe('custom domain races', () => {
  it('locks writes while the list cannot be read', async () => {
    let fail = true
    const { wrapper, calls } = await mountAt(CustomDomains, '/t/acme/custom-domains', c => {
      if (fail) return { status: 503, body: { statusCode: 503, errorCode: 'temporarily_unavailable', message: 'down' } }
      if (c.url.endsWith('/custom-domains/default')) return { status: 200, body: { domain: 'acme.example.test' } }
      return { status: 200, body: [] }
    })
    expect(wrapper.text()).toContain('changes are paused')
    expect((wrapper.find('form button[type=submit]').element as HTMLButtonElement).disabled).toBe(true)
    await wrapper.find('input#domain-name').setValue('draft.acme.test')
    fail = false
    await wrapper.findAll('button').find(b => b.text().includes('Try again'))!.trigger('click')
    await flushPromises()
    expect((wrapper.find('form button[type=submit]').element as HTMLButtonElement).disabled).toBe(false)
    expect((wrapper.find('input#domain-name').element as HTMLInputElement).value).toBe('draft.acme.test')
    expect(calls.filter(c => c.method === 'POST')).toHaveLength(0)
  })

  it('ignores a slow reply for the previous domain', async () => {
    let release!: () => void
    const slow = new Promise<void>(r => { release = r })
    const { wrapper, router } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_2', async c => {
      if (c.url.endsWith('/cd_1')) {
        await slow
        return { status: 200, body: domain({ custom_domain_id: 'cd_1', domain: 'stale.acme.test' }) }
      }
      return { status: 200, body: domain({ custom_domain_id: 'cd_2', domain: 'fresh.acme.test' }) }
    })
    await router.push('/t/acme/custom-domains/cd_1')
    await router.push('/t/acme/custom-domains/cd_2')
    await flushPromises()
    release()
    await flushPromises()
    expect(wrapper.text()).toContain('fresh.acme.test')
    expect(wrapper.text()).not.toContain('stale.acme.test')
  })
})
