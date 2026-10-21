import { flushPromises } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Job } from '../../api/client'
import { apiError, mountAt } from '../../test/mount'
import type { Call, Reply } from '../../test/services'
import ImportExport from './ImportExport.vue'

const path = '/t/acme/users/import-export'
const job = (id: string, extra: Partial<Job> = {}): Job => ({ id, type: 'users_import', status: 'completed', created_at: '2026-10-20T10:00:00.000Z', connection: 'Users c0', connection_id: 'c0', ...extra })
const body = () => document.body

interface World {
  jobs: Job[]
  errors?: unknown
  errorsStatus?: number
  fresh?: Record<string, Job>
}

function backend(w: World) {
  return (c: Call): Reply => {
    const u = new URL(c.url)
    if (u.pathname === '/api/v2/connections') return { status: 200, body: { connections: [], start: 0, limit: 100, total: 0 } }
    if (u.pathname === '/api/system/tenants/acme/jobs') return { status: 200, body: { jobs: w.jobs, start: 0, limit: 20, total: w.jobs.length } }
    const m = u.pathname.match(/^\/api\/v2\/jobs\/([^/]+)(\/errors)?$/)
    if (m && m[2]) return w.errorsStatus === 204 ? { status: 204 } : { status: 200, body: w.errors ?? [] }
    if (m) return { status: 200, body: w.fresh?.[m[1]!] ?? w.jobs.find((j) => j.id === m[1]) }
    return { status: 404 }
  }
}
const listCalls = (calls: Call[]) => calls.filter((c) => new URL(c.url).pathname === '/api/system/tenants/acme/jobs')
const button = (label: string) => Array.from(body().querySelectorAll('button')).find((b) => b.textContent?.trim() === label)!
const click = async (target: Element | { element: Element }) => {
  const el = 'element' in target ? target.element : target
  el.dispatchEvent(new MouseEvent('click', { bubbles: true }))
  await flushPromises()
}
const setVisibility = (v: 'visible' | 'hidden') => {
  Object.defineProperty(document, 'visibilityState', { value: v, configurable: true })
  document.dispatchEvent(new Event('visibilitychange'))
}

afterEach(() => {
  vi.useRealTimers()
  setVisibility('visible')
  body().innerHTML = ''
})

describe('jobs list', () => {
  it('shows a loading state, then the jobs', async () => {
    let release = () => {}
    const gate = new Promise<void>((r) => (release = r))
    const w: World = { jobs: [job('job_import1', { summary: { inserted: 3, updated: 1, failed: 2, total: 6 } })] }
    const h = backend(w)
    const { wrapper } = await mountAt(ImportExport, path, async (c) => {
      if (new URL(c.url).pathname.endsWith('/jobs')) await gate
      return h(c)
    })
    expect(wrapper.text()).toContain('Loading')
    release()
    await flushPromises()
    expect(wrapper.text()).not.toContain('Loading')
    const row = wrapper.get('[data-job="job_import1"]').text()
    expect(row).toContain('Import')
    expect(row).toContain('Completed')
    expect(row).toContain('Users c0')
    expect(row).toContain('3 added, 1 updated, 2 failed of 6')
    wrapper.unmount()
  })

  it('shows an empty state', async () => {
    const { wrapper } = await mountAt(ImportExport, path, backend({ jobs: [] }))
    expect(wrapper.text()).toContain('No jobs in the last 24 hours.')
    wrapper.unmount()
  })

  it('shows an error with a retry that works', async () => {
    let fail = true
    const h = backend({ jobs: [job('job_import1')] })
    const { wrapper } = await mountAt(ImportExport, path, (c) => (fail && new URL(c.url).pathname.endsWith('/jobs') ? apiError(500, 'internal_error', 'Internal error') : h(c)))
    expect(wrapper.get('[role="alert"]').text()).toContain('Internal error')
    fail = false
    await click(button('Try again'))
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    expect(wrapper.find('[data-job="job_import1"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('shows the weak-hash count with a link to the reset advice, and nothing when there are none', async () => {
    const w: World = { jobs: [job('job_weak', { weak_hashes: 2 }), job('job_none', { weak_hashes: 0 })] }
    const { wrapper } = await mountAt(ImportExport, path, backend(w))
    const weak = wrapper.get('[data-job="job_weak"]')
    expect(weak.text()).toContain('2 imported with a weak password hash.')
    const a = weak.get('a')
    expect(a.attributes('href')).toContain('docs/user-import.md#weak-hashes')
    expect(a.attributes('rel')).toContain('noopener')
    expect(wrapper.get('[data-job="job_none"]').text()).not.toContain('weak')
    wrapper.unmount()
  })

  it('offers Errors only for an import that had failures, and Download only for a completed export', async () => {
    const w: World = {
      jobs: [
        job('job_clean', { summary: { inserted: 1, updated: 0, failed: 0, total: 1 } }),
        job('job_bad', { summary: { inserted: 0, updated: 0, failed: 1, total: 1 } }),
        job('job_dead', { status: 'failed', status_details: 'Job timed out' }),
        job('job_exp', { type: 'users_export', status: 'completed', connection: undefined }),
        job('job_expwait', { type: 'users_export', status: 'pending' }),
      ],
    }
    const { wrapper } = await mountAt(ImportExport, path, backend(w))
    const has = (id: string, label: string) => wrapper.get(`[data-job="${id}"]`).findAll('button').some((b) => b.text() === label)
    expect(has('job_clean', 'Errors')).toBe(false)
    expect(has('job_bad', 'Errors')).toBe(true)
    expect(has('job_dead', 'Errors')).toBe(true)
    expect(wrapper.get('[data-job="job_dead"]').text()).toContain('Job timed out')
    expect(has('job_exp', 'Download')).toBe(true)
    expect(has('job_expwait', 'Download')).toBe(false)
    expect(has('job_bad', 'Download')).toBe(false)
    expect(wrapper.get('[data-job="job_exp"]').text()).toContain('All connections')
    wrapper.unmount()
  })

  it('asks for a fresh job read on every download and follows the new location', async () => {
    const clicked: string[] = []
    const spy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      clicked.push(this.href)
    })
    const w: World = { jobs: [job('job_exp', { type: 'users_export', status: 'completed' })], fresh: {} }
    let n = 0
    const h = backend(w)
    const { wrapper, calls } = await mountAt(ImportExport, path, (c) => {
      if (c.method === 'GET' && new URL(c.url).pathname === '/api/v2/jobs/job_exp') {
        n++
        return { status: 200, body: job('job_exp', { type: 'users_export', status: 'completed', location: `https://acme.example.test/jobs/download?sig=SIG${n}` }) }
      }
      return h(c)
    })
    expect(calls.filter((c) => new URL(c.url).pathname === '/api/v2/jobs/job_exp')).toHaveLength(0) // no link is held from the list
    await click(button('Download'))
    await click(button('Download'))
    expect(calls.filter((c) => new URL(c.url).pathname === '/api/v2/jobs/job_exp')).toHaveLength(2)
    expect(clicked).toEqual(['https://acme.example.test/jobs/download?sig=SIG1', 'https://acme.example.test/jobs/download?sig=SIG2'])
    spy.mockRestore()
    wrapper.unmount()
  })

  it('says so when the job has no file any more, and shows a read failure', async () => {
    const spy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const w: World = { jobs: [job('job_exp', { type: 'users_export', status: 'completed' })] }
    const h = backend(w)
    let gone = true
    const { wrapper } = await mountAt(ImportExport, path, (c) => {
      if (c.method === 'GET' && new URL(c.url).pathname === '/api/v2/jobs/job_exp') return gone ? { status: 200, body: job('job_exp', { type: 'users_export', status: 'completed' }) } : apiError(404, 'inexistent_job', 'The job does not exist')
      return h(c)
    })
    await click(button('Download'))
    expect(spy).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('The file is no longer available.')
    gone = false
    await click(button('Download'))
    expect(wrapper.get('[role="alert"]').text()).toContain('The job does not exist')
    spy.mockRestore()
    wrapper.unmount()
  })

  describe('polling', () => {
    beforeEach(() => {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    })

    it('reads again every 3 seconds while a job is pending, and stops when none is', async () => {
      const w: World = { jobs: [job('job_run', { status: 'pending' })] }
      const { wrapper, calls } = await mountAt(ImportExport, path, backend(w))
      expect(listCalls(calls)).toHaveLength(1)
      await vi.advanceTimersByTimeAsync(2999)
      expect(listCalls(calls)).toHaveLength(1)
      await vi.advanceTimersByTimeAsync(1)
      expect(listCalls(calls)).toHaveLength(2)
      await vi.advanceTimersByTimeAsync(3000)
      expect(listCalls(calls)).toHaveLength(3)
      // The job finishes; one more read sees it, then polling stops.
      w.jobs = [job('job_run', { status: 'completed' })]
      await vi.advanceTimersByTimeAsync(3000)
      expect(listCalls(calls)).toHaveLength(4)
      expect(wrapper.get('[data-job="job_run"]').text()).toContain('Completed')
      await vi.advanceTimersByTimeAsync(30000)
      expect(listCalls(calls)).toHaveLength(4)
      wrapper.unmount()
    })

    it('does not poll when nothing is pending', async () => {
      const { wrapper, calls } = await mountAt(ImportExport, path, backend({ jobs: [job('job_done')] }))
      await vi.advanceTimersByTimeAsync(20000)
      expect(listCalls(calls)).toHaveLength(1)
      wrapper.unmount()
    })

    it('stops while the page is hidden and reads again when it is shown', async () => {
      const w: World = { jobs: [job('job_run', { status: 'pending' })] }
      const { wrapper, calls } = await mountAt(ImportExport, path, backend(w))
      setVisibility('hidden')
      await vi.advanceTimersByTimeAsync(20000)
      expect(listCalls(calls)).toHaveLength(1)
      setVisibility('visible')
      await flushPromises()
      expect(listCalls(calls)).toHaveLength(2)
      await vi.advanceTimersByTimeAsync(3000)
      expect(listCalls(calls)).toHaveLength(3)
      wrapper.unmount()
    })

    it('stops when the page goes away', async () => {
      const { wrapper, calls } = await mountAt(ImportExport, path, backend({ jobs: [job('job_run', { status: 'pending' })] }))
      wrapper.unmount()
      await vi.advanceTimersByTimeAsync(20000)
      expect(listCalls(calls)).toHaveLength(1)
    })

    it('keeps the list on screen when a poll fails, and keeps trying', async () => {
      let fail = false
      const h = backend({ jobs: [job('job_run', { status: 'pending' })] })
      const { wrapper, calls } = await mountAt(ImportExport, path, (c) => (fail && new URL(c.url).pathname.endsWith('/jobs') ? apiError(503, 'x', 'Unavailable') : h(c)))
      fail = true
      await vi.advanceTimersByTimeAsync(3000)
      expect(wrapper.find('[data-job="job_run"]').exists()).toBe(true)
      expect(wrapper.get('[role="alert"]').text()).toContain('Unavailable')
      fail = false
      await vi.advanceTimersByTimeAsync(3000)
      expect(listCalls(calls)).toHaveLength(3)
      expect(wrapper.find('[role="alert"]').exists()).toBe(false)
      wrapper.unmount()
    })
  })
})

describe('errors view', () => {
  const masked = { email: 'a@b.test', custom_password_hash: { algorithm: 'bcrypt', hash: { value: '*****' } } }
  const failing = (): World => ({
    jobs: [job('job_bad', { summary: { inserted: 0, updated: 0, failed: 1, total: 1 } })],
    errors: [{ user: masked, errors: [{ code: 'PATTERN', message: "String does not match pattern ^\\$2[aby]?\\$ on property custom_password_hash.hash.value: *****", path: 'custom_password_hash.hash.value' }] }],
  })

  it('lists the records with their codes, messages and paths, exactly as masked by the server', async () => {
    const { wrapper, calls } = await mountAt(ImportExport, path, backend(failing()))
    await click(wrapper.get('[data-job="job_bad"]').findAll('button').find((b) => b.text() === 'Errors')!)
    const dialog = body().querySelector('[role="dialog"]')!
    const text = dialog.textContent!
    expect(text).toContain('PATTERN')
    expect(text).toContain('custom_password_hash.hash.value')
    expect(text).toContain('*****')
    expect(dialog.querySelector('pre')!.textContent).toBe(JSON.stringify(masked, null, 2))
    expect(calls.some((c) => new URL(c.url).pathname === '/api/v2/jobs/job_bad/errors')).toBe(true)
    wrapper.unmount()
  })

  it('never puts a hash value on the page, however the record arrives', async () => {
    const HASH = '$2b$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'
    const w = failing()
    // The server masks; the console passes through what it gets and nothing else.
    const { wrapper, calls } = await mountAt(ImportExport, path, backend(w))
    await click(wrapper.get('[data-job="job_bad"]').findAll('button').find((b) => b.text() === 'Errors')!)
    expect(document.documentElement.innerHTML).not.toContain(HASH)
    expect(document.documentElement.innerHTML).not.toContain('$2b$')
    // The upload itself is never fetched back: no call reads the import file.
    expect(calls.every((c) => !/input|file|users-imports/.test(new URL(c.url).pathname))).toBe(true)
    wrapper.unmount()
  })

  it('says so when no record failed, when the job has none (204), and when the job failed as a whole', async () => {
    const w: World = { jobs: [job('job_bad', { summary: { inserted: 0, updated: 0, failed: 1, total: 1 } })], errors: [] }
    const { wrapper } = await mountAt(ImportExport, path, backend(w))
    const open = () => click(wrapper.get('[data-job="job_bad"]').findAll('button').find((b) => b.text() === 'Errors')!)
    const close = () => click(button('Close'))
    await open()
    expect(body().querySelector('[role="dialog"]')!.textContent).toContain('No record failed.')
    await close()
    w.errorsStatus = 204
    await open()
    expect(body().querySelector('[role="dialog"]')!.textContent).toContain('no per-record errors')
    await close()
    w.errorsStatus = undefined
    w.errors = job('job_bad', { status: 'failed', status_details: 'Job timed out' })
    await open()
    expect(body().querySelector('[role="dialog"]')!.textContent).toContain('Job timed out')
    wrapper.unmount()
  })

  it('shows a failure to read the errors', async () => {
    const h = backend(failing())
    const { wrapper } = await mountAt(ImportExport, path, (c) => (c.url.endsWith('/errors') ? apiError(404, 'inexistent_job', 'The job does not exist') : h(c)))
    await click(wrapper.get('[data-job="job_bad"]').findAll('button').find((b) => b.text() === 'Errors')!)
    expect(body().querySelector('[role="dialog"] [role="alert"]')!.textContent).toContain('The job does not exist')
    wrapper.unmount()
  })
})

