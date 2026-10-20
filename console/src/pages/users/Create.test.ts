import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { connection, type Call } from '../../test/services'
import Create from './Create.vue'

const plain = connection('c0')
const withName = connection('c1', { options: { ...(connection('c1').options as object), requires_username: true } })

function backend(created: Call[] = []) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections') {
      expect(u.searchParams.get('strategy')).toBe('auth0')
      return { status: 200, body: { connections: [plain, withName], start: 0, limit: 100, total: 2 } }
    }
    if (u.pathname === '/api/v2/users' && c.method === 'POST') {
      created.push(c)
      return { status: 201, body: { user_id: 'auth0|abc' } }
    }
    return { status: 404 }
  }
}

async function fill(wrapper: Awaited<ReturnType<typeof mountAt>>['wrapper'], conn: string, email: string, password: string) {
  await wrapper.get('#user-connection').setValue(conn)
  await wrapper.get('#user-email').setValue(email)
  await wrapper.get('#user-password').setValue(password)
}

describe('user create', () => {
  it('offers database connections and shows the username only when required', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/users/new', backend())
    expect(wrapper.findAll('#user-connection option').map((o) => o.text())).toEqual(['Connection', 'Users c0', 'Users c1'])
    expect(wrapper.find('#user-username').exists()).toBe(false)
    await wrapper.get('#user-connection').setValue('Users c1')
    expect(wrapper.find('#user-username').exists()).toBe(true)
    await wrapper.get('#user-connection').setValue('Users c0')
    expect(wrapper.find('#user-username').exists()).toBe(false)
    wrapper.unmount()
  })

  it('validates before sending', async () => {
    const created: Call[] = []
    const { wrapper } = await mountAt(Create, '/t/acme/users/new', backend(created))
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#user-connection-error').text()).toBe('Choose a connection.')
    expect(wrapper.get('#user-email-error').text()).toBe('Enter an email address.')
    expect(wrapper.get('#user-password-error').text()).toBe('Enter a password.')
    await wrapper.get('#user-connection').setValue('Users c1')
    await wrapper.get('#user-email').setValue('nope')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#user-email-error').text()).toBe('Enter a valid email address.')
    expect(wrapper.get('#user-username-error').text()).toBe('Enter a username.')
    expect(created).toHaveLength(0)
    wrapper.unmount()
  })

  it('checks the password against the connection as you type', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/users/new', backend())
    await wrapper.get('#user-connection').setValue('Users c0')
    await wrapper.get('#user-password').setValue('short')
    expect(wrapper.get('[data-rule=length]').attributes('data-ok')).toBe('false')
    expect(wrapper.get('[data-rule=length]').text()).toContain('At least 15 characters')
    await wrapper.get('#user-password').setValue('a-long-enough-pass')
    expect(wrapper.get('[data-rule=length]').attributes('data-ok')).toBe('true')
    wrapper.unmount()
  })

  it('creates the user and opens it', async () => {
    const created: Call[] = []
    const { wrapper, router } = await mountAt(Create, '/t/acme/users/new', backend(created))
    await fill(wrapper, 'Users c1', ' ada@example.test ', 'a-long-enough-pass')
    await wrapper.get('#user-username').setValue('ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(created[0]!.body).toEqual({ connection: 'Users c1', email: 'ada@example.test', password: 'a-long-enough-pass', username: 'ada', verify_email: true })
    expect(router.currentRoute.value.name).toBe('user')
    expect(router.currentRoute.value.params.id).toBe('auth0|abc')
    wrapper.unmount()
  })

  it('leaves the username out when the connection does not ask, and honours the verification box', async () => {
    const created: Call[] = []
    const { wrapper } = await mountAt(Create, '/t/acme/users/new', backend(created))
    await fill(wrapper, 'Users c0', 'a@example.test', 'a-long-enough-pass')
    await wrapper.get('input[type=checkbox]').setValue(false)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(created[0]!.body).toEqual({ connection: 'Users c0', email: 'a@example.test', password: 'a-long-enough-pass', verify_email: false })
    wrapper.unmount()
  })

  it('shows a conflict by the email and a refused password by the password', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/users/new', (c) =>
      c.method === 'POST' ? apiError(409, 'auth0_idp_error', 'The user already exists.') : backend()(c),
    )
    await fill(wrapper, 'Users c0', 'a@example.test', 'a-long-enough-pass')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('#user-email-error').text()).toBe('The user already exists.')
    wrapper.unmount()
    const b = await mountAt(Create, '/t/acme/users/new', (c) =>
      c.method === 'POST' ? { status: 400, body: { statusCode: 400, error: 'Bad Request', message: 'PasswordStrengthError: Password is too weak' } } : backend()(c),
    )
    await fill(b.wrapper, 'Users c0', 'a@example.test', 'a-long-enough-pass')
    await b.wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(b.wrapper.get('#user-password-error').text()).toContain('too weak')
    b.wrapper.unmount()
  })

  it('says so when there is no database connection', async () => {
    const { wrapper } = await mountAt(Create, '/t/acme/users/new', () => ({ status: 200, body: { connections: [], start: 0, limit: 100, total: 0 } }))
    expect(wrapper.text()).toContain('no database connection yet')
    expect(wrapper.find('form').exists()).toBe(false)
    wrapper.unmount()
  })
})
