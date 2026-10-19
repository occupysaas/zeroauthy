import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import Actions from './Actions.vue'
import { assertPreviewInert } from './preview'
import { mountAt } from '../../test/mount'

const never = () => ({ status: 500, body: {} })

describe('PlannedPage', () => {
  it('renders title, banner and placeholder without calling the API', async () => {
    const { wrapper, calls } = await mountAt(Actions, '/t/acme/actions', never)
    expect(wrapper.get('h1').text()).toBe('Actions')
    const banner = wrapper.get('[role=status]').text()
    expect(banner).toContain('Planned · later')
    expect(banner).toContain('/api/v2/actions')
    expect(wrapper.text()).toContain('This section is planned. Its page will be designed when its API is built.')
    expect(calls).toEqual([])
  })
})

describe('assertPreviewInert', () => {
  const page = (inner: () => unknown[]) => mount(defineComponent({ render: () => h('div', inner() as never) }))
  it('accepts disabled controls and live nav', () => {
    const w = page(() => [h('input', { disabled: true }), h('div', { 'data-preview-nav': '' }, [h('button', 'Tab')])])
    expect(() => assertPreviewInert(w)).not.toThrow()
  })
  it('rejects an enabled control outside nav', () => {
    const w = page(() => [h('input')])
    expect(() => assertPreviewInert(w)).toThrow()
  })
})
