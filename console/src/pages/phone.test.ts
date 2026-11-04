import { defineComponent, h } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { routes } from '../router'
import { mountAt, apiError } from '../test/mount'
import { tenant, type Call, type Reply } from '../test/services'
import SettingsTab from './connections/SettingsTab.vue'
import Mfa from './security/Mfa.vue'
import DetailsTab from './users/DetailsTab.vue'
import ConnectionList from './connections/List.vue'
import UserMfa from './users/UserMfa.vue'
const provider = {
  id: 'p1',
  name: 'twilio',
  disabled: false,
  configuration: { sid: 'AC123', default_from: '+15551234567', delivery_methods: ['text', 'voice'] },
  credentials: { auth_token: 'must-never-display' },
}
function routePage(name: string) {
  return routes.find((r) => r.name === name)?.component ?? defineComponent({ render: () => h('div') })
}
function reply(c: Call): Reply {
  const u = new URL(c.url)
  if (u.pathname.endsWith('/branding/phone/providers/p1') && c.method === 'PATCH')
    return { status: 200, body: provider }
  if (u.pathname.endsWith('/branding/phone/providers'))
    return { status: 200, body: c.method === 'GET' ? { providers: [provider] } : provider }
  if (u.pathname.endsWith('/clients')) return { status: 200, body: { clients: [], total: 0 } }
  if (u.pathname.endsWith('/actions/actions'))
    return {
      status: 200,
      body: { actions: [{ id: 'act1', name: 'Phone Action', deployed_version: { id: 'v1' } }], total: 1 },
    }
  if (u.pathname.endsWith('/bindings'))
    return {
      status: 200,
      body: {
        bindings: [
          {
            ref: { type: 'action_id', value: 'act1' },
            display_name: 'Phone Action',
            action: { id: 'act1', name: 'Phone Action' },
          },
        ],
        total: 1,
      },
    }
  if (u.pathname.endsWith('/branding/phone/templates'))
    return {
      status: 200,
      body: {
        templates: [
          {
            id: 't1',
            type: 'otp_verify',
            disabled: false,
            content: { body: { text: 'Code: {{ code }}', voice: 'Say {{ code }}' } },
          },
        ],
      },
    }
  if (u.pathname.endsWith('/connections'))
    return {
      status: 200,
      body: {
        connections: [
          { id: 'c1', name: 'email', strategy: 'email' },
          { id: 's1', name: 'sms', strategy: 'sms' },
        ],
        total: 2,
      },
    }
  if (u.pathname.endsWith('/connections/c1'))
    return {
      status: 200,
      body: {
        id: 'c1',
        name: 'email',
        strategy: 'email',
        options: { totp: { length: 6, time_step: 180 }, email: { subject: 'Sign in', body: '{{ code }}' } },
      },
    }
  if (u.pathname.endsWith('/connections/s1'))
    return {
      status: 200,
      body: { id: 's1', name: 'sms', strategy: 'sms', options: { provider: 'twilio', twilio_sid: 'AC123' } },
    }
  if (u.pathname.endsWith('/guardian/factors'))
    return {
      status: 200,
      body: [
        { name: 'sms', enabled: false },
        { name: 'phone', enabled: false },
      ],
    }
  if (u.pathname.endsWith('/guardian/policies')) return { status: 200, body: [] }
  if (u.pathname.endsWith('/tenants/settings')) return { status: 200, body: { phone_consolidated_experience: true } }
  return { status: 202, body: { message: 'Accepted' } }
}
afterEach(() => {
  document.body.innerHTML = ''
})
it('edits Twilio credentials write-only and sends a provider try', async () => {
  const { wrapper, calls } = await mountAt(routePage('phone-providers'), '/t/acme/phone-providers', reply)
  expect(wrapper.find('#phone-provider-name').exists()).toBe(true)
  expect(wrapper.get<HTMLInputElement>('#credential-auth_token').element.value).toBe('')
  expect(wrapper.html()).not.toContain('must-never-display')
  await wrapper.get('#credential-auth_token').setValue('replacement')
  await wrapper.get('#save-phone-provider').trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'PATCH')?.body).toMatchObject({ credentials: { auth_token: 'replacement' } })
  await wrapper.get('#phone-test-to').setValue('+15551234567')
  await wrapper.get('#try-phone-provider').trigger('click')
  await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ to: '+15551234567', delivery_method: 'text' })
  wrapper.unmount()
})
it('supports SNS secrets and Custom deployed Action picker and binding', async () => {
  const { wrapper, calls } = await mountAt(routePage('phone-providers'), '/t/acme/phone-providers', reply)
  expect(wrapper.find('#phone-provider-name').exists()).toBe(true)
  await wrapper.get('#phone-provider-name').setValue('sns')
  expect(wrapper.find('#credential-secret_access_key').exists()).toBe(true)
  expect(wrapper.find('#configuration-region').exists()).toBe(true)
  await wrapper.get('#phone-provider-name').setValue('custom')
  await flushPromises()
  expect(wrapper.get('#phone-action').text()).toContain('Phone Action')
  await wrapper.get('#phone-action').setValue('act1')
  await wrapper.get('#save-phone-provider').trigger('click')
  await flushPromises()
  expect(
    calls.some((c) => c.method === 'PATCH' && c.url.endsWith('/bindings') && JSON.stringify(c.body).includes('act1'))
  ).toBe(true)
  wrapper.unmount()
})
it('edits phone templates with escaped preview and saved-template try', async () => {
  const { wrapper, calls } = await mountAt(routePage('phone-templates'), '/t/acme/phone-templates', reply)
  expect(wrapper.find('#phone-template-text').exists()).toBe(true)
  await wrapper.get('#phone-template-text').setValue('<b>Code {{ code }}</b>')
  expect(wrapper.get('[data-phone-preview]').text()).toContain('<b>Code 123456</b>')
  expect(wrapper.find('[data-phone-preview] b').exists()).toBe(false)
  await wrapper.get('#save-phone-template').trigger('click')
  await flushPromises()
  expect(calls.some((c) => c.method === 'PATCH' && c.url.endsWith('/templates/t1'))).toBe(true)
  await wrapper.get('#phone-template-to').setValue('+15551234567')
  await wrapper.get('#try-phone-template').trigger('click')
  await flushPromises()
  expect(calls.at(-1)?.url).toContain('/templates/t1/try')
  wrapper.unmount()
})
it.each(['email', 'sms'])('configures passwordless %s, projects lists, sends a test', async (strategy) => {
  const { wrapper, calls } = await mountAt(
    routePage('passwordless-' + strategy),
    '/t/acme/passwordless/' + strategy,
    reply
  )
  expect(wrapper.find('#passwordless-length').exists()).toBe(true)
  const list = calls.find((c) => new URL(c.url).pathname.endsWith('/connections'))!
  const fields = new URL(list.url).searchParams.get('fields')
  expect(fields).toBe('id,name,strategy')
  expect(fields).not.toContain('options')
  await wrapper.get('#passwordless-length').setValue('8')
  await wrapper.get('#save-passwordless').trigger('click')
  await flushPromises()
  expect(calls.some((c) => c.method === 'PATCH' && JSON.stringify(c.body).includes('"length":8'))).toBe(true)
  await wrapper.get('#passwordless-client').setValue('client1')
  await wrapper.get('#passwordless-to').setValue(strategy === 'email' ? 'test@example.test' : '+15551234567')
  await wrapper.get('#try-passwordless').trigger('click')
  await flushPromises()
  expect(calls.at(-1)?.url).toContain('/passwordless/start')
  expect(calls.at(-1)?.body).toMatchObject({ client_id: 'client1', connection: strategy })
  wrapper.unmount()
})
it('disables SMS and voice factors with explanation without a working provider', async () => {
  const { wrapper } = await mountAt(Mfa, '/t/acme/mfa', (c) =>
    new URL(c.url).pathname.endsWith('/branding/phone/providers') ? { status: 200, body: { providers: [] } } : reply(c)
  )
  expect(wrapper.get('#factor-sms').attributes('disabled')).toBeDefined()
  expect(wrapper.get('#phone-voice').attributes('disabled')).toBeDefined()
  expect(wrapper.text()).toContain('Configure an enabled phone provider')
  wrapper.unmount()
})
it('shows refused phone identifier conflicts as a list and preserves options', async () => {
  const page = defineComponent({
    render: () =>
      h(SettingsTab, {
        tenant: tenant('acme'),
        connection: {
          id: 'db',
          name: 'db',
          strategy: 'auth0',
          is_domain_connection: false,
          options: { attributes: { email: { identifier: { active: true } } } },
        },
      }),
  })
  const { wrapper, calls } = await mountAt(page, '/t/acme/connections/db', () =>
    apiError(
      400,
      'invalid_body',
      'Phone identifier conflicts: [{"user_ids":["auth0|one","auth0|two"],"reason":"duplicate"}]'
    )
  )
  expect(wrapper.find('#phone-identifier').exists()).toBe(true)
  await wrapper.get('#phone-identifier').setValue(true)
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)?.body).toMatchObject({
    options: {
      attributes: { email: { identifier: { active: true } }, phone_number: { identifier: { active: true } } },
    },
  })
  expect(wrapper.get('[data-phone-conflicts]').text()).toContain('auth0|one')
  expect(wrapper.get('[data-phone-conflicts]').text()).toContain('duplicate')
  wrapper.unmount()
})
it('edits user phone fields and displays verification and phone MFA enrollment', async () => {
  const page = defineComponent({
    render: () =>
      h(DetailsTab, {
        tenant: tenant('acme'),
        user: { user_id: 'auth0|one', phone_number: '+15551234567', phone_verified: true },
      }),
  })
  const { wrapper, calls } = await mountAt(page, '/t/acme/users/auth0%7Cone', () => ({
    status: 200,
    body: { user_id: 'auth0|one' },
  }))
  expect(wrapper.get('[data-testid=phone]').text()).toContain('verified')
  expect(wrapper.find('#user-phone').exists()).toBe(true)
  await wrapper.get('#user-phone').setValue('+15557654321')
  await wrapper.get('form').trigger('submit')
  await flushPromises()
  expect(calls.at(-1)?.body).toMatchObject({ phone_number: '+15557654321', phone_verified: false })
  wrapper.unmount()
  const methods = defineComponent({
    render: () => h(UserMfa, { tenant: tenant('acme'), user: { user_id: 'auth0|one' } }),
  })
  const m = await mountAt(methods, '/t/acme/users/auth0%7Cone', () => ({
    status: 200,
    body: [{ id: 'phone|one', type: 'phone', phone_number: '+15551234567' }],
  }))
  expect(m.wrapper.text()).toContain('+15551234567')
  m.wrapper.unmount()
})

it('connection list requests only public display fields, never credentials or options', async () => {
  const { wrapper, calls } = await mountAt(ConnectionList, '/t/acme/connections', (c) =>
    new URL(c.url).pathname.endsWith('/clients') ? { status: 200, body: { clients: [], total: 0 } } : reply(c)
  )
  const list = calls.find((c) => new URL(c.url).pathname.endsWith('/connections'))!
  expect(new URL(list.url).searchParams.get('fields')).toBe('id,name,strategy,is_domain_connection')
  expect(new URL(list.url).searchParams.get('include_fields')).toBe('true')
  wrapper.unmount()
})
it('supports an enabled SMS provider while disabling unsupported voice delivery', async () => {
  const { wrapper, calls } = await mountAt(Mfa, '/t/acme/mfa', (c) =>
    new URL(c.url).pathname.endsWith('/branding/phone/providers')
      ? {
          status: 200,
          body: {
            providers: [
              {
                id: 'sns1',
                name: 'sns',
                disabled: false,
                configuration: { region: 'us-east-1', delivery_methods: ['text'] },
              },
            ],
          },
        }
      : reply(c)
  )
  expect(wrapper.get('#factor-sms').attributes('disabled')).toBeUndefined()
  expect(wrapper.get('#phone-voice').attributes('disabled')).toBeDefined()
  await wrapper.get('#phone-sms').setValue(false)
  await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ message_types: [] })
  wrapper.unmount()
})
it('does not offer custom phone delivery when its deployed Action binding is missing', async () => {
  const { wrapper } = await mountAt(Mfa, '/t/acme/mfa', (c) =>
    new URL(c.url).pathname.endsWith('/branding/phone/providers')
      ? {
          status: 200,
          body: {
            providers: [
              {
                id: 'custom1',
                name: 'custom',
                disabled: false,
                configuration: { delivery_methods: ['text', 'voice'] },
              },
            ],
          },
        }
      : new URL(c.url).pathname.endsWith('/bindings')
        ? { status: 200, body: { bindings: [], total: 0 } }
        : reply(c)
  )
  expect(wrapper.get('#factor-sms').attributes('disabled')).toBeDefined()
  wrapper.unmount()
})
it('allows clearing email overrides and exposes enabled applications for passwordless', async () => {
  const { wrapper, calls } = await mountAt(routePage('passwordless-email'), '/t/acme/passwordless/email', reply)
  await wrapper.get('#passwordless-subject').setValue('')
  await wrapper.get('#save-passwordless').trigger('click')
  await flushPromises()
  const options = (calls.find((c) => c.method === 'PATCH')?.body as { options: { email: Record<string, unknown> } })
    .options
  expect(options.email).not.toHaveProperty('subject')
  expect(wrapper.find('[data-passwordless-applications]').exists()).toBe(true)
  wrapper.unmount()
})
it('sends only SNS credentials and text delivery when changing provider', async () => {
  const { wrapper, calls } = await mountAt(routePage('phone-providers'), '/t/acme/phone-providers', reply)
  await wrapper.get('#credential-auth_token').setValue('discard-me')
  await wrapper.get('#phone-provider-name').setValue('sns')
  await wrapper.get('#configuration-region').setValue('us-east-1')
  await wrapper.get('#credential-access_key_id').setValue('new-key')
  await wrapper.get('#credential-secret_access_key').setValue('new-secret')
  await wrapper.get('#save-phone-provider').trigger('click')
  await flushPromises()
  expect(calls.find((c) => c.method === 'PATCH')?.body).toMatchObject({
    name: 'sns',
    credentials: { access_key_id: 'new-key', secret_access_key: 'new-secret' },
    configuration: { region: 'us-east-1', delivery_methods: ['text'] },
  })
  expect(JSON.stringify(calls.find((c) => c.method === 'PATCH')?.body)).not.toContain('discard-me')
  wrapper.unmount()
})
it('ignores a stale provider response and clears secrets across tenant navigation', async () => {
  let finish!: (r: Reply) => void,
    hold = false
  const { wrapper, router } = await mountAt(routePage('phone-providers'), '/t/acme/phone-providers', (c) =>
    hold && c.method === 'PATCH'
      ? new Promise((r) => {
          finish = r
        })
      : reply(c)
  )
  await wrapper.get('#credential-auth_token').setValue('old-secret')
  hold = true
  await wrapper.get('#save-phone-provider').trigger('click')
  await flushPromises()
  await router.push('/t/system/phone-providers')
  await flushPromises()
  finish({ status: 200, body: { ...provider, configuration: { ...provider.configuration, sid: 'OLD-RESPONSE' } } })
  await flushPromises()
  expect(wrapper.html()).not.toContain('old-secret')
  expect(wrapper.get<HTMLInputElement>('#configuration-sid').element.value).not.toBe('OLD-RESPONSE')
  wrapper.unmount()
})
it('recognizes legacy Guardian Twilio configuration when unified delivery is off', async () => {
  const { wrapper } = await mountAt(Mfa, '/t/acme/mfa', (c) => {
    const path = new URL(c.url).pathname
    if (path.endsWith('/tenants/settings')) return { status: 200, body: { phone_consolidated_experience: false } }
    if (path.endsWith('/branding/phone/providers')) return { status: 200, body: { providers: [] } }
    if (path.endsWith('/phone/selected-provider')) return { status: 200, body: { provider: 'twilio' } }
    if (path.endsWith('/phone/providers/twilio')) return { status: 200, body: { sid: 'AC123', from: '+15551234567' } }
    return reply(c)
  })
  expect(wrapper.get('#factor-sms').attributes('disabled')).toBeUndefined()
  expect(wrapper.get('#phone-voice').attributes('disabled')).toBeUndefined()
  wrapper.unmount()
})
it('resets test delivery when a provider changes from voice to SMS only', async () => {
  const { wrapper, calls } = await mountAt(routePage('phone-providers'), '/t/acme/phone-providers', (c) =>
    c.method === 'PATCH' && c.url.endsWith('/providers/p1')
      ? { status: 200, body: { id: 'p1', ...(c.body as object) } }
      : reply(c)
  )
  await wrapper.get('#phone-delivery').setValue('voice')
  await wrapper.get('#phone-provider-name').setValue('sns')
  await wrapper.get('#configuration-region').setValue('us-east-1')
  await wrapper.get('#credential-access_key_id').setValue('key')
  await wrapper.get('#credential-secret_access_key').setValue('secret')
  await wrapper.get('#save-phone-provider').trigger('click')
  await flushPromises()
  await wrapper.get('#phone-test-to').setValue('+15551234567')
  await wrapper.get('#try-phone-provider').trigger('click')
  await flushPromises()
  expect(calls.at(-1)?.body).toEqual({ to: '+15551234567', delivery_method: 'text' })
  wrapper.unmount()
})
