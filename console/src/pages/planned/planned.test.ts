import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import PlannedPage from './PlannedPage.vue'
import PreviewTable from './PreviewTable.vue'
import Toggle from '../../ui/Toggle.vue'
import { assertPreviewInert } from './preview'
import { plannedPages } from './index'
import { isPlanned, sections } from '../../layout/sections'
import { mountAt } from '../../test/mount'

const never = () => ({ status: 500, body: {} })

describe('PlannedPage slots', () => {
  it('shows slots and breadcrumb, hiding the placeholder', async () => {
    const page = defineComponent({
      render: () => h(PlannedPage, { sectionKey: 'mfa' }, { default: () => h('p', 'preview body'), actions: () => h('button', { disabled: true }, 'Create user') }),
    })
    const { wrapper } = await mountAt(page, '/t/acme/mfa', never)
    expect(wrapper.text()).toContain('Security')
    expect(wrapper.text()).toContain('Create user')
    expect(wrapper.text()).toContain('preview body')
    expect(wrapper.text()).not.toContain('This section is planned.')
    expect(wrapper.get('[role=status]').text()).toContain('Planned · later')
  })
})

describe('PreviewTable', () => {
  it('renders headers and one spanning empty row', () => {
    const w = mount(PreviewTable, { props: { columns: ['A', 'B', 'C'], empty: 'Nothing yet.' } })
    expect(w.findAll('th').map((x) => x.text())).toEqual(['A', 'B', 'C'])
    expect(w.findAll('tbody tr')).toHaveLength(1)
    const td = w.get('tbody td')
    expect(td.attributes('colspan')).toBe('3')
    expect(td.text()).toBe('Nothing yet.')
  })
})

describe('Toggle', () => {
  it('is a named switch and honours disabled', () => {
    const w = mount(Toggle, { props: { label: 'Enable', disabled: true }, attachTo: document.body })
    const sw = w.get('[role=switch]')
    expect(document.querySelector(`label[for="${sw.attributes('id')}"]`)?.textContent).toBe('Enable')
    expect(sw.attributes('disabled')).toBeDefined()
    w.unmount()
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

it('keeps only sections that are still planned', () => {
  expect(Object.keys(plannedPages).sort()).toEqual(['logs', 'mfa'])
  expect(isPlanned(sections.find(s => s.key === 'emails')!)).toBe(false)
  for (const key of ['settings', 'attack-protection', 'organizations']) expect(isPlanned(sections.find(s => s.key === key)!)).toBe(false)
})
