import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { confirmPrompt, mountAt } from '../../test/mount'
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


describe('async detail progress', () => {
  it('polls progress while preserving edited settings and stops on unmount', async () => {
    vi.useFakeTimers()
    try {
      let ready = false
      const { wrapper, calls } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', () => ({ status: 200, body: domain({ status: ready ? 'ready' : 'pending_verification' }) }))
      await wrapper.find('#metadata').setValue('draft=keep')
      ready = true
      await vi.advanceTimersByTimeAsync(5000)
      await flushPromises()
      expect(wrapper.text()).toContain('Ready')
      expect((wrapper.find('#metadata').element as HTMLTextAreaElement).value).toBe('draft=keep')
      wrapper.unmount()
      const count = calls.length
      await vi.advanceTimersByTimeAsync(30000)
      expect(calls.length).toBe(count)
    } finally { vi.useRealTimers() }
  })

  it('ignores an old settings response after navigation', async () => {
    let release!: () => void
    const blocked = new Promise<void>(r => { release = r })
    const { wrapper, router } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', async c => {
      if (c.method === 'PATCH') { await blocked; return { status: 200, body: domain({ domain: 'stale.acme.test' }) } }
      return { status: 200, body: domain({ custom_domain_id: c.url.endsWith('/cd_2') ? 'cd_2' : 'cd_1', domain: c.url.endsWith('/cd_2') ? 'fresh.acme.test' : 'first.acme.test' }) }
    })
    await wrapper.find('form').trigger('submit')
    await router.push('/t/acme/custom-domains/cd_2')
    await flushPromises()
    release()
    await flushPromises()
    expect(wrapper.text()).toContain('fresh.acme.test')
    expect(wrapper.text()).not.toContain('stale.acme.test')
    wrapper.unmount()
  })
})

describe('mutation navigation boundaries', () => {
  it('does not navigate back when an old deletion completes', async () => {
    let release!: () => void
    const blocked = new Promise<void>(r => { release = r })
    try {
      const { wrapper, router } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', async c => {
        if (c.method === 'DELETE') { await blocked; return { status: 204 } }
        return { status: 200, body: domain() }
      })
      await wrapper.findAll('button').find(b => b.text().includes('Delete domain'))!.trigger('click')
      await flushPromises()
      await confirmPrompt()
      await router.push('/t/acme/custom-domains/cd_2')
      await flushPromises()
      release()
      await flushPromises()
      expect(router.currentRoute.value.fullPath).toBe('/t/acme/custom-domains/cd_2')
      wrapper.unmount()
    } finally { vi.unstubAllGlobals() }
  })

  it('does not navigate to the old tenant when its creation completes', async () => {
    let release!: () => void
    const blocked = new Promise<void>(r => { release = r })
    const { wrapper, router } = await mountAt(CustomDomains, '/t/acme/custom-domains', async c => {
      if (c.method === 'POST') { await blocked; return { status: 201, body: domain() } }
      if (c.url.endsWith('/default')) return { status: 200, body: { domain: 'acme.example.test' } }
      return { status: 200, body: [] }
    })
    await wrapper.find('#domain-name').setValue('login.acme.test')
    await wrapper.find('form').trigger('submit')
    await router.push('/t/system/custom-domains')
    await flushPromises()
    release()
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/t/system/custom-domains')
    wrapper.unmount()
  })

  it('locks detail writes after a failed poll while retaining the draft', async () => {
    vi.useFakeTimers()
    try {
      let fail = false
      const { wrapper } = await mountAt(DomainDetail, '/t/acme/custom-domains/cd_1', () => fail ? { status: 503, body: { message: 'down' } } : { status: 200, body: domain() })
      await wrapper.find('#metadata').setValue('draft=keep')
      fail = true
      await vi.advanceTimersByTimeAsync(5000)
      await flushPromises()
      expect((wrapper.find('form button[type=submit]').element as HTMLButtonElement).disabled).toBe(true)
      fail = false
      await vi.advanceTimersByTimeAsync(5000)
      await flushPromises()
      expect((wrapper.find('form button[type=submit]').element as HTMLButtonElement).disabled).toBe(false)
      expect((wrapper.find('#metadata').element as HTMLTextAreaElement).value).toBe('draft=keep')
      wrapper.unmount()
    } finally { vi.useRealTimers() }
  })
})

it('refreshes list readiness and cancels its poll on unmount', async () => {
  vi.useFakeTimers()
  try {
    let ready = false
    const { wrapper, calls } = await mountAt(CustomDomains, '/t/acme/custom-domains', c => c.url.endsWith('/default') ? { status: 200, body: { domain: 'acme.example.test' } } : { status: 200, body: [domain({ status: ready ? 'ready' : 'pending_verification' })] })
    ready = true
    await vi.advanceTimersByTimeAsync(5000)
    await flushPromises()
    expect(wrapper.text()).toContain('Ready')
    wrapper.unmount()
    const count = calls.length
    await vi.advanceTimersByTimeAsync(30000)
    expect(calls.length).toBe(count)
  } finally { vi.useRealTimers() }
})
