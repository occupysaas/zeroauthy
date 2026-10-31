import { expect, it } from 'vitest'
import LogsList from '../logs/LogsList.vue'
import { plannedPages } from './index'
import { mountAt } from '../../test/mount'

it('ships Logs with a live table, search and date controls', async () => {
  expect(plannedPages.logs).toBeUndefined()
  const { wrapper, calls } = await mountAt(LogsList, '/t/acme/logs', () => ({ status: 200, body: { logs: [], total: 0 } }))
  expect(wrapper.get('h1').text()).toBe('Logs')
  expect(wrapper.findAll('th').map(h => h.text())).toEqual(['Time (UTC)', 'Event type', 'Description', 'Application', 'Connection', 'User ID'])
  expect(wrapper.get('#log-q').attributes('disabled')).toBeUndefined()
  expect(wrapper.findAll('input[type=date]')).toHaveLength(2)
  expect(wrapper.findAll('input[type=date]').every(i => i.attributes('disabled') === undefined)).toBe(true)
  expect(calls).toHaveLength(1)
  wrapper.unmount()
})
