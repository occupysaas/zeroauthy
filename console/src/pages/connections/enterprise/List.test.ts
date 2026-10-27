import { describe, expect, it } from 'vitest'
import { mountAt } from '../../../test/mount'
import { connection } from '../../../test/services'
import SocialList from '../social/List.vue'
import EnterpriseList from './List.vue'

const all = ['auth0', 'google-oauth2', 'oauth2', 'windowslive', 'oidc', 'waad'].map(strategy => connection(strategy, { name: strategy, strategy }))
describe('Connection audience grouping', () => {
  it.each([['social', ['google-oauth2', 'oauth2', 'windowslive']], ['enterprise', ['oidc', 'waad']]])('groups %s and routes each detail deliberately', async (audience, strategies) => {
    const { wrapper } = await mountAt(audience === 'enterprise' ? EnterpriseList : SocialList, `/t/acme/${audience}`, () => ({ status: 200, body: { connections: all, total: all.length } }))
    expect(wrapper.findAll('tbody a').map(a => a.text())).toEqual(strategies)
    expect(wrapper.findAll('tbody a').map(a => a.attributes('href'))).toEqual(strategies.map(s => `/admin/t/acme/${audience}/${s}`))
    wrapper.unmount()
  })
})
