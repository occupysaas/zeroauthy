import { flushPromises } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { mountAt } from '../../test/mount'
import { resourceServer } from '../../test/services'
import Detail from './Detail.vue'

const path = '/t/acme/apis/r1'

function tabTo(name: string) {
  const trigger = Array.from(document.body.querySelectorAll<HTMLElement>('[role="tab"]')).find((x) => x.textContent?.trim() === name)!
  trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
  trigger.focus()
}

afterEach(() => { document.body.innerHTML = '' })

describe('API signing algorithm', () => {
  it('keeps the HS256 secret hidden until revealed and never stores it in the browser', async () => {
    const secret = 'S'.repeat(43)
    const { wrapper } = await mountAt(Detail, path, () => ({ status: 200, body: resourceServer('r1', { signing_alg: 'HS256', signing_secret: secret }) }))
    tabTo('Settings')
    await flushPromises()
    const shown = () => wrapper.find('[data-testid="signing-secret"]').text()
    expect(shown()).not.toContain('S')
    await wrapper.findAll('button').find((b) => b.text() === 'Reveal')!.trigger('click')
    expect(shown()).toBe(secret)
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(secret)
    wrapper.unmount()
  })

  it('patches the algorithm, sending a supplied secret only for HS256', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, (c) => ({ status: 200, body: resourceServer('r1', c.method === 'PATCH' ? { signing_alg: 'HS256' } : {}) }))
    tabTo('Settings')
    await flushPromises()
    await wrapper.find('#api-alg').setValue('HS256')
    await wrapper.find('#api-secret').setValue('a-secret-of-enough-length')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'PATCH')!.body).toMatchObject({ signing_alg: 'HS256', signing_secret: 'a-secret-of-enough-length' })
    wrapper.unmount()
  })

  it('does not resend the algorithm when unchanged', async () => {
    const { wrapper, calls } = await mountAt(Detail, path, () => ({ status: 200, body: resourceServer('r1') }))
    tabTo('Settings')
    await flushPromises()
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(calls.find((c) => c.method === 'PATCH')!.body).not.toHaveProperty('signing_alg')
    wrapper.unmount()
  })
})
