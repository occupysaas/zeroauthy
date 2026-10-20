import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { fakeServices } from '../../test/services'
import SearchHelp from './SearchHelp.vue'

function mountHelp() {
  const { i18n } = fakeServices(() => ({ status: 404 }))
  return mount(SearchHelp, { attachTo: document.body, global: { plugins: [i18n] } })
}

describe('search help', () => {
  it('closes on a click outside, not on a click inside', async () => {
    const wrapper = mountHelp()
    await wrapper.get('button').trigger('click')
    expect(wrapper.find('#search-help').exists()).toBe(true)
    await wrapper.get('#search-help').trigger('click')
    expect(wrapper.find('#search-help').exists()).toBe(true)
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await wrapper.vm.$nextTick()
    expect(wrapper.find('#search-help').exists()).toBe(false)
    wrapper.unmount()
  })

  it('closes on Esc and returns focus to the toggle', async () => {
    const wrapper = mountHelp()
    const toggle = wrapper.get('button')
    await toggle.trigger('click')
    ;(wrapper.get('#search-help a').element as HTMLElement).focus()
    await wrapper.get('#search-help a').trigger('keydown', { key: 'Escape' })
    expect(wrapper.find('#search-help').exists()).toBe(false)
    expect(document.activeElement).toBe(toggle.element)
    wrapper.unmount()
  })
})
