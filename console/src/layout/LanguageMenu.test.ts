import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { fakeServices } from '../test/services'
import LanguageMenu from './LanguageMenu.vue'

describe('LanguageMenu', () => {
  it('lists the locales and applies the choice', async () => {
    const { pinia, i18n } = fakeServices(() => ({ status: 404 }))
    const wrapper = mount(LanguageMenu, { attachTo: document.body, global: { plugins: [pinia, i18n] } })
    const trigger = wrapper.get('button')
    expect(trigger.attributes('aria-label')).toBe('Language')
    expect(trigger.find('svg').exists()).toBe(true)

    await trigger.trigger('keydown', { key: 'Enter' })
    await flushPromises()
    const items = Array.from(document.body.querySelectorAll<HTMLElement>('[role="menuitemradio"]'))
    expect(items.map((i) => i.textContent?.trim())).toEqual(['English'])

    items[0].click()
    await flushPromises()
    expect(document.documentElement.lang).toBe('en')
    expect(localStorage.getItem('zeroauthy.console.locale')).toBe('en')
    wrapper.unmount()
  })
})
