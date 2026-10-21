import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { apiError, mountAt } from '../../test/mount'
import { connection, type Call } from '../../test/services'
import ImportExport from './ImportExport.vue'
import { MAX_IMPORT_FILE_BYTES } from './jobs'

const plain = connection('c0')
const custom = connection('c1', { options: { ...(connection('c1').options as object), enabledDatabaseCustomization: true } })
const customImport = connection('c2', { options: { ...(connection('c2').options as object), enabledDatabaseCustomization: true, import_mode: true } })

function backend(posted: Call[] = [], reply: ReturnType<typeof apiError> | null = null) {
  return (c: Call) => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections') return { status: 200, body: { connections: [plain, custom, customImport], start: 0, limit: 100, total: 3 } }
    if (u.pathname === '/api/v2/jobs/users-imports' && c.method === 'POST') {
      posted.push(c)
      return reply ?? { status: 202, body: { id: 'job_abcdefgh12345678', type: 'users_import', status: 'pending', created_at: '2026-10-20T10:00:00.000Z' } }
    }
    return { status: 404 }
  }
}

async function pickFile(wrapper: Awaited<ReturnType<typeof mountAt>>['wrapper'], file: File) {
  const input = wrapper.get<HTMLInputElement>('#import-file')
  Object.defineProperty(input.element, 'files', { value: [file], configurable: true })
  await input.trigger('change')
}

// The form takes its tenant from the page, so the page is mounted (its job list answers empty).
function mountForm(handler = backend()) {
  return mountAt(ImportExport, '/t/acme/users/import-export', (c) => (new URL(c.url).pathname.endsWith('/jobs') && c.method === 'GET' ? { status: 200, body: { jobs: [], start: 0, limit: 20, total: 0 } } : handler(c)))
}

describe('import form', () => {
  it('offers database connections, leaving out custom ones that are not in import mode', async () => {
    const { wrapper } = await mountForm()
    expect(wrapper.findAll('#import-connection option').map((o) => o.text())).toEqual(['Choose a connection…', 'Users c0', 'Users c2 (custom database)'])
    wrapper.unmount()
  })

  it('asks for a file and a connection before uploading anything', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await wrapper.get('form').trigger('submit')
    expect(wrapper.text()).toContain('Choose a file to import.')
    expect(wrapper.text()).toContain('Choose a connection.')
    expect(posted).toHaveLength(0)
    wrapper.unmount()
  })

  it('refuses a file above the limit before upload, naming the limit', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await pickFile(wrapper, new File([new Uint8Array(MAX_IMPORT_FILE_BYTES + 1)], 'big.json'))
    await wrapper.get('#import-connection').setValue('c0')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('#import-file-error').text()).toContain('511,000 bytes')
    expect(MAX_IMPORT_FILE_BYTES).toBe(511000)
    expect(posted).toHaveLength(0)
    wrapper.unmount()
  })

  it('refuses an empty file', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await pickFile(wrapper, new File([], 'none.json'))
    await wrapper.get('#import-connection').setValue('c0')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.get('#import-file-error').text()).toContain('empty')
    expect(posted).toHaveLength(0)
    wrapper.unmount()
  })

  it('accepts a file of exactly the limit', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await pickFile(wrapper, new File([new Uint8Array(MAX_IMPORT_FILE_BYTES)], 'edge.json'))
    await wrapper.get('#import-connection').setValue('c0')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(posted).toHaveLength(1)
    wrapper.unmount()
  })

  it('uploads the file with the connection and both switches, then reports the job', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    const text = '[{"email":"a@b.test"}]'
    await pickFile(wrapper, new File([text], 'users.json', { type: 'application/json' }))
    await wrapper.get('#import-connection').setValue('c0')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(posted).toHaveLength(1)
    const f = posted[0]!.form!
    expect(new URL(posted[0]!.url).host).toBe('acme.example.test')
    expect(f.connection_id).toBe('c0')
    expect(f.upsert).toBe('false')
    expect(f.send_completion_email).toBe('true')
    expect(await (f.users as File).text()).toBe(text)
    expect(wrapper.get('#import-title').element.parentElement!.textContent).toContain('job_abcdefgh12345678')
    wrapper.unmount()
  })

  it('sends the switches as set', async () => {
    const posted: Call[] = []
    const { wrapper } = await mountForm(backend(posted))
    await pickFile(wrapper, new File(['[{}]'], 'users.json'))
    await wrapper.get('#import-connection').setValue('c2')
    for (const sw of wrapper.get('#import-title').element.parentElement!.querySelectorAll<HTMLElement>('[role="switch"]')) sw.click()
    await flushPromises()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(posted[0]!.form!.upsert).toBe('true')
    expect(posted[0]!.form!.send_completion_email).toBe('false')
    wrapper.unmount()
  })

  it("shows the server's refusal and keeps the form", async () => {
    const { wrapper } = await mountForm(backend([], apiError(400, 'operation_not_supported', 'Users file must not be empty.')))
    await pickFile(wrapper, new File(['[{}]'], 'users.json'))
    await wrapper.get('#import-connection').setValue('c0')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Users file must not be empty.')
    expect((wrapper.get('#import-connection').element as HTMLSelectElement).value).toBe('c0')
    wrapper.unmount()
  })
})

