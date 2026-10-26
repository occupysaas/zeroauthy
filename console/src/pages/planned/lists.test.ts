import { describe, expect, it } from 'vitest'
import { plannedPages } from './index'
import { assertPreviewInert } from './preview'
import { mountAt } from '../../test/mount'

const never = () => ({ status: 500, body: {} })

// key, title, column headers, empty text, header buttons
const tables: [string, string, string[], string, string[]][] = [
  ['roles', 'Roles', ['Name', 'Description'], 'Roles will appear here.', ['Create role']],
  ['organizations', 'Organizations', ['Name', 'Display name'], 'Organizations will appear here.', ['Create organization']],
  ['logs', 'Logs', ['Event', 'Description', 'Date', 'Connection', 'Application'], 'Log events will appear here.', ['Log streams']],
]

describe('list-style planned previews', () => {
  it.each(tables)('%s shows its table, empty state and inert controls', async (key, title, headers, empty, buttons) => {
    const { wrapper, calls } = await mountAt(plannedPages[key]!, `/t/acme/${key}`, never)
    expect(wrapper.get('h1').text()).toBe(title)
    expect(wrapper.findAll('th').map((x) => x.text())).toEqual(headers)
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    expect(wrapper.get('tbody td').text()).toBe(empty)
    const labels = wrapper.findAll('button').map((b) => b.text())
    for (const b of buttons) expect(labels).toContain(b)
    assertPreviewInert(wrapper)
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })

  it('social lists provider tiles in order, all disabled', async () => {
    const { wrapper, calls } = await mountAt(plannedPages.social!, '/t/acme/social', never)
    expect(wrapper.get('h1').text()).toBe('Social')
    expect(wrapper.findAll('li button').map((b) => b.text())).toEqual(['Generic OAuth 2 / OIDC', 'Google', 'Apple', 'Facebook', 'Microsoft'])
    expect(wrapper.findAll('button').map((b) => b.text())).toContain('Create connection')
    assertPreviewInert(wrapper)
    expect(calls.length).toBe(0)
    wrapper.unmount()
  })

  it('logs has a disabled type select and date range', async () => {
    const { wrapper } = await mountAt(plannedPages.logs!, '/t/acme/logs', never)
    expect(wrapper.get('select').attributes('disabled')).toBeDefined()
    expect(wrapper.findAll('input[type=date]')).toHaveLength(2)
    wrapper.unmount()
  })
})
