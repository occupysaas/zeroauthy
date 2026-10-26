import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountAt } from '../../test/mount'
import CustomDomains from './CustomDomains.vue'
import DomainDetail from './DomainDetail.vue'
import { domain } from './fixtures'

afterEach(() => { document.body.innerHTML = ''; vi.unstubAllGlobals() })

const ready = domain({ custom_domain_id: 'cd_2', domain: 'login.acme.test', status: 'ready', verification: { methods: [], status: 'verified' }, certificate: { status: 'provisioned', renews_before: '2027-01-24T00:00:00Z' } })

describe('custom domains list', () => {
  it('lists domains, adds one and opens it', async () => {
    const { wrapper, calls, router } = await mountAt(CustomDomains, '/t/acme/custom-domains', c => {
      if (c.method === 'POST') return { status: 201, body: domain({ custom_domain_id: 'cd_9', domain: 'new.acme.test' }) }
      if (c.url.endsWith('/custom-domains/default')) return { status: 200, body: { domain: 'acme.example.test' } }
      return { status: 200, body: [domain(), ready] }
    })
    expect(wrapper.text()).toContain('id.acme.test')
    expect(wrapper.text()).toContain('Pending verification')
    expect(wrapper.text()).toContain('Ready')
    const input = wrapper.find('input#domain-name')
    expect(wrapper.find('label[for=domain-name]').exists()).toBe(true)
    await input.setValue('new.acme.test')
    await wrapper.find('select#domain-type').setValue('self_managed_certs')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const post = calls.find(c => c.method === 'POST')
    expect(post?.body).toEqual({ domain: 'new.acme.test', type: 'self_managed_certs' })
    expect(router.currentRoute.value.name).toBe('custom-domain')
    expect(router.currentRoute.value.params.id).toBe('cd_9')
  })

  it('offers only ready domains as default and can reset to canonical', async () => {
    let current = 'acme.example.test'
    const { wrapper, calls } = await mountAt(CustomDomains, '/t/acme/custom-domains', c => {
      if (c.method === 'PATCH') {
        current = (c.body as { domain: string }).domain
        return { status: 200, body: current === 'login.acme.test' ? { ...ready, is_default: true } : { domain: current } }
      }
      if (c.url.endsWith('/custom-domains/default')) return { status: 200, body: current === 'login.acme.test' ? { ...ready, is_default: true } : { domain: current } }
      return { status: 200, body: [domain(), { ...ready, is_default: current === 'login.acme.test' }] }
    })
    const options = wrapper.findAll('select#default-domain option').map(o => o.attributes('value'))
    expect(options).toEqual(['acme.example.test', 'login.acme.test'])
    await wrapper.find('select#default-domain').setValue('login.acme.test')
    await flushPromises()
    expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ domain: 'login.acme.test' })
    await wrapper.findAll('button').find(b => b.text().includes('canonical'))!.trigger('click')
    await flushPromises()
    expect(calls.filter(c => c.method === 'PATCH').at(-1)?.body).toEqual({ domain: 'acme.example.test' })
  })

  it('shows a configured default that is not usable', async () => {
    const { wrapper } = await mountAt(CustomDomains, '/t/acme/custom-domains', c => {
      if (c.url.endsWith('/custom-domains/default')) return { status: 200, body: { ...ready, status: 'pending_verification', is_default: true } }
      return { status: 200, body: [{ ...ready, status: 'pending_verification', is_default: true }] }
    })
    expect(wrapper.text()).toContain('login.acme.test is configured as the default but is not usable right now')
  })
})

describe('custom domain detail', () => {
  it('shows DNS and certificate progress, saves settings and deletes', async () => {
    vi.stubGlobal('confirm', vi.fn(() => true))
    const managed = domain({ status: 'pending_verification', certificate: { status: 'provisioning_failed', error_msg: 'the certificate authority rate limited issuance' } })
    const { wrapper, calls, router } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', c => {
      if (c.method === 'PATCH') return { status: 200, body: { ...managed, custom_client_ip_header: null } }
      if (c.method === 'DELETE') return { status: 204 }
      return { status: 200, body: managed }
    })
    const text = wrapper.text()
    expect(text).toContain('_zeroauthy-domain-verification.id.acme.test')
    expect(text).toContain('zeroauthy-domain-verification=abc')
    expect(text).toContain('cd-01ab.origin.example.test')
    expect(text).toContain('Issuance failed (retrying)')
    expect(text).toContain('rate limited')
    expect(text).toContain('Stored for compatibility')
    await wrapper.find('select#client-ip').setValue('')
    await wrapper.find('textarea#metadata').setValue('brand=Acme\nregion = eu')
    await wrapper.find('form#domain-settings').trigger('submit')
    await flushPromises()
    expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ custom_client_ip_header: null, domain_metadata: { brand: 'Acme', region: 'eu' }, relying_party_identifier: 'id.acme.test' })
    await wrapper.findAll('button').find(b => b.text().includes('Delete domain'))!.trigger('click')
    await flushPromises()
    expect(calls.some(c => c.method === 'DELETE')).toBe(true)
    expect(router.currentRoute.value.name).toBe('custom-domains')
  })

  it('reports certificate expiry and test results', async () => {
    const { wrapper } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_2', c => {
      if (c.url.endsWith('/test')) return { status: 200, body: { success: false, message: 'the discovery issuer does not match the domain' } }
      return { status: 200, body: ready }
    })
    expect(wrapper.text()).toContain('Issued')
    expect(wrapper.text()).toContain('2027-01-24')
    await wrapper.findAll('button').find(b => b.text().includes('Test domain'))!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Test failed: the discovery issuer does not match the domain')
  })
})
