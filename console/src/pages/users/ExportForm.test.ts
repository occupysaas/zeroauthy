import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { connection, type Call } from '../../test/services'
import ImportExport from './ImportExport.vue'

function backend(posted: Call[] = [], reply: ReturnType<typeof apiError> | null = null) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections') return { status: 200, body: { connections: [connection('c0'), connection('c1')], start: 0, limit: 100, total: 2 } }
    if (u.pathname.endsWith('/jobs') && c.method === 'GET') return { status: 200, body: { jobs: [], start: 0, limit: 20, total: 0 } }
    if (u.pathname === '/api/v2/jobs/users-exports' && c.method === 'POST') {
      posted.push(c)
      return reply ?? { status: 200, body: { id: 'job_exportexport1234', type: 'users_export', status: 'pending', created_at: '2026-10-20T10:00:00.000Z' } }
    }
    return { status: 404 }
  }
}
const mountForm = (handler = backend()) => mountAt(ImportExport, '/t/acme/users/import-export', handler)
const submit = async (w: Awaited<ReturnType<typeof mountForm>>['wrapper']) => {
  await w.get('#export-title').element.parentElement!.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }))
  await flushPromises()
}
const addButton = (w: Awaited<ReturnType<typeof mountForm>>['wrapper']) => w.findAll('button').find((b) => b.text() === 'Add a field')!

describe('export form', () => {
  it('sends only the format when nothing is changed, so the server writes the standard columns', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await submit(wrapper)
    expect(posted).toHaveLength(1)
    expect(new URL(posted[0]!.url).host).toBe('acme.example.test')
    expect(posted[0]!.body).toEqual({ format: 'csv' })
    expect(wrapper.get('#export-title').element.parentElement!.textContent).toContain('job_exportexport1234')
    wrapper.unmount()
  })

  it('sends the connection, format and limit', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await wrapper.get('#export-connection').setValue('c1')
    await wrapper.get('#export-format').setValue('json')
    await wrapper.get('#export-limit').setValue('250')
    await submit(wrapper)
    expect(posted[0]!.body).toEqual({ format: 'json', connection_id: 'c1', limit: 250 })
    wrapper.unmount()
  })

  it.each(['0', '-3', '1.5', 'many'])('refuses the limit %s', async (v) => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await wrapper.get('#export-limit').setValue(v)
    await submit(wrapper)
    expect(wrapper.get('#export-limit-error').text()).toContain('whole number')
    expect(posted).toHaveLength(0)
    wrapper.unmount()
  })

  it('sends the chosen fields, a metadata subfield and export_as', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    // Drop every default but two.
    for (const box of wrapper.findAll<HTMLInputElement>('fieldset input[type="checkbox"]')) {
      const name = box.element.nextElementSibling!.textContent
      if (name !== 'user_id' && name !== 'email') await box.setValue(false)
    }
    await addButton(wrapper).trigger('click')
    await wrapper.get('[id^="export-extra-name-"]').setValue('user_metadata.plan')
    await wrapper.get('[id^="export-extra-as-"]').setValue('plan')
    await addButton(wrapper).trigger('click')
    await wrapper.findAll('[id^="export-extra-name-"]')[1]!.setValue('app_metadata.tier')
    await submit(wrapper)
    expect(posted[0]!.body).toEqual({
      format: 'csv',
      fields: [{ name: 'user_id' }, { name: 'email' }, { name: 'user_metadata.plan', export_as: 'plan' }, { name: 'app_metadata.tier' }],
    })
    wrapper.unmount()
  })

  it('asks for a subfield, not the whole metadata object, in a CSV', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await addButton(wrapper).trigger('click')
    await wrapper.get('[id^="export-extra-name-"]').setValue('user_metadata')
    await submit(wrapper)
    expect(wrapper.get('#export-fields-error').text()).toContain('user_metadata.plan')
    expect(posted).toHaveLength(0)
    // JSON can hold the whole object.
    await wrapper.get('#export-format').setValue('json')
    await submit(wrapper)
    expect(posted).toHaveLength(1)
    wrapper.unmount()
  })

  it('needs a name for every added field and at least one field', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await addButton(wrapper).trigger('click')
    await submit(wrapper)
    expect(wrapper.get('#export-fields-error').text()).toContain('name for every added field')
    for (const box of wrapper.findAll<HTMLInputElement>('fieldset input[type="checkbox"]')) await box.setValue(false)
    await wrapper.findAll('button').find((b) => b.text() === 'Remove')!.trigger('click')
    await submit(wrapper)
    expect(wrapper.get('#export-fields-error').text()).toContain('at least one field')
    expect(posted).toHaveLength(0)
    wrapper.unmount()
  })

  it('stops at 30 fields', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    // 19 defaults are ticked; 11 more reach 30.
    for (let i = 0; i < 11; i++) {
      await addButton(wrapper).trigger('click')
      await wrapper.findAll('[id^="export-extra-name-"]')[i]!.setValue('user_metadata.k' + i)
    }
    expect(wrapper.text()).toContain('30 of 30 fields')
    expect(addButton(wrapper).element.disabled).toBe(true)
    await addButton(wrapper).trigger('click')
    expect(wrapper.findAll('[id^="export-extra-name-"]')).toHaveLength(11)
    // Unticked defaults cannot be re-ticked past the limit.
    const first = wrapper.findAll<HTMLInputElement>('fieldset input[type="checkbox"]')[0]!
    await first.setValue(false)
    expect(addButton(wrapper).element.disabled).toBe(false)
    const others = wrapper.findAll<HTMLInputElement>('fieldset input[type="checkbox"]').filter((b) => !b.element.checked)
    expect(others[0]!.element.disabled).toBe(false)
    await addButton(wrapper).trigger('click')
    expect(wrapper.findAll<HTMLInputElement>('fieldset input[type="checkbox"]').filter((b) => !b.element.checked).every((b) => b.element.disabled)).toBe(true)
    await submit(wrapper)
    expect(posted).toHaveLength(0) // the new field has no name yet
    wrapper.unmount()
  })

  it("shows the server's refusal", async () => {
    const { wrapper } = await mountForm(backend([], apiError(400, 'invalid_body', 'Payload validation error: limit')))
    await submit(wrapper)
    expect(wrapper.get('[role="alert"]').text()).toContain('Payload validation error: limit')
    wrapper.unmount()
  })
})
