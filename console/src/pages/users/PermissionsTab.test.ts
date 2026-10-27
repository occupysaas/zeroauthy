// User direct/inherited permission behavior is exercised alongside the shared
// permission editor in roles/PermissionsTab.test.ts.
import { expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { mountAt } from '../../test/mount'
import { tenant } from '../../test/services'
import PermissionsTab from './PermissionsTab.vue'
it('renders an explicit empty permission state', async () => {
  const page = defineComponent({ render: () => h(PermissionsTab, { tenant: tenant('acme'), user: { user_id: 'auth0|1' } }) })
  const { wrapper } = await mountAt(page, '/t/acme/users/auth0%7C1', (c) => ({
    status: 200,
    body:
      new URL(c.url).pathname === '/api/v2/resource-servers'
        ? { resource_servers: [], total: 0 }
        : { permissions: [], total: 0, start: 0, limit: 20 },
  }))
  expect(wrapper.text()).toContain('No permissions assigned')
  wrapper.unmount()
})
