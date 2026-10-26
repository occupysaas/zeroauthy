import { flushPromises } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { h } from 'vue'
import { mountAt } from '../../test/mount'
import Editor from './Editor.vue'
import Branding from './Branding.vue'

const page = (kind: string) => ({ render: () => h(Editor, { kind }) })

describe('Branding editors', () => {
  for (const kind of ['branding', 'theme', 'template', 'prompts', 'text', 'partials']) {
    it(`loads and saves ${kind} without rendering authored HTML`, async () => {
      const { wrapper, calls } = await mountAt(page(kind), '/t/acme/branding', c => {
        if (c.method === 'GET') return { status: 200, body: kind === 'template' ? { template: '<p>Saved</p>' } : kind === 'theme' ? { themeId: 'theme-1' } : {} }
        return { status: 200, body: {} }
      })
      const json = wrapper.find('textarea')
      await json.setValue(kind === 'template' ? '<p>Draft</p>' : '{}')
      await wrapper.find('form').trigger('submit')
      await flushPromises()
      expect(calls.filter(c => c.method !== 'GET')).toHaveLength(1)
      expect(wrapper.find('p').text()).not.toBe('Draft')
      expect(wrapper.text()).toContain('Changes saved')
      wrapper.unmount()
    })
  }

  it('locks writes after a failed read and offers retry', async () => {
    const { wrapper, calls } = await mountAt(page('branding'), '/t/acme/branding', () => ({ status: 403, body: { message: 'Permission denied' } }))
    expect(wrapper.text()).toContain('Permission denied')
    expect(wrapper.find('button[type=submit]').attributes('disabled')).toBeDefined()
    expect(calls).toHaveLength(1)
    wrapper.unmount()
  })

  it('retains a draft and refreshes once after an uncertain save without retrying it', async () => {
    const { wrapper, calls } = await mountAt(page('template'), '/t/acme/branding', c => {
      if (c.method === 'GET') return { status: 200, body: { template: '<p>Saved</p>' } }
      throw new TypeError('Failed to fetch')
    })
    await wrapper.find('textarea').setValue('<p>Unsaved draft</p>')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).toBe('<p>Unsaved draft</p>')
    expect(calls.filter(c => c.method === 'PUT')).toHaveLength(1)
    expect(calls.filter(c => c.method === 'GET')).toHaveLength(2)
    expect(wrapper.text()).toContain('The saved state was refreshed')
    wrapper.unmount()
  })

  it('shows seed ownership and keeps editor drafts across tabs', async () => {
    const { wrapper } = await mountAt(Branding, '/t/acme/branding', () => ({ status: 200, body: {} }), { seeded: true })
    expect(wrapper.text()).toContain('seed')
    const area = wrapper.find('textarea')
    await area.setValue('{"logo_url":"https://example.test/draft.svg"}')
    const tabs = wrapper.findAll('[role=tab]')
    await tabs.find(t => t.text() === 'Prompts')!.trigger('click')
    await tabs.find(t => t.text() === 'Settings')!.trigger('click')
    expect((area.element as HTMLTextAreaElement).value).toContain('draft.svg')
    wrapper.unmount()
  })
})

describe('Branding lifecycle and stale responses', () => {
  it('creates an active theme, patches by ID and deletes that ID', async () => {
    const { wrapper, calls } = await mountAt(page('theme'), '/t/acme/branding', c => {
      if (c.method === 'GET') return { status: 404, body: {} }
      if (c.method === 'POST') return { status: 200, body: { themeId: 'new-theme', displayName: 'New' } }
      return { status: 204 }
    })
    await wrapper.find('textarea').setValue('{"displayName":"New"}')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.find(c => c.method === 'POST')?.url).toMatch(/\/branding\/themes$/)
    await wrapper.find('form').trigger('submit'); await flushPromises()
    expect(calls.find(c => c.method === 'PATCH')?.url).toMatch(/\/themes\/new-theme$/)
    await wrapper.findAll('button').find(b => b.text() === 'Delete theme')!.trigger('click'); await flushPromises()
    expect(calls.find(c => c.method === 'DELETE')?.url).toMatch(/\/themes\/new-theme$/)
    expect(wrapper.text()).toContain('Deleting the default clears its pointer')
    expect(wrapper.text()).toContain('widget.social_buttons_layout')
    wrapper.unmount()
  })

  for (const kind of ['template', 'text', 'partials']) {
    it(`clears ${kind} with the resource's correct method`, async () => {
      const { wrapper, calls } = await mountAt(page(kind), '/t/acme/branding', c => ({ status: c.method === 'DELETE' ? 204 : 200, body: c.method === 'DELETE' ? undefined : {} }))
      await wrapper.findAll('button').find(b => b.text() === 'Clear configuration')!.trigger('click'); await flushPromises()
      const writes = calls.filter(c => c.method !== 'GET')
      expect(writes).toHaveLength(1)
      expect(writes[0]?.method).toBe(kind === 'template' ? 'DELETE' : 'PUT')
      if (kind !== 'template') expect(writes[0]?.body).toEqual({})
      wrapper.unmount()
    })
  }

  it('discards a late tenant load after the target changes', async () => {
    let resolve!: (r: { status: number; body: unknown }) => void
    const { wrapper, router } = await mountAt(page('branding'), '/t/acme/branding', c => {
      if (c.url.includes('acme.example')) return new Promise(r => { resolve = r })
      return { status: 200, body: { logo_url: 'https://example.test/system.svg' } }
    })
    await router.push('/t/system/branding'); await flushPromises()
    resolve({ status: 200, body: { logo_url: 'https://private.example.test/acme.svg' } }); await flushPromises()
    expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).toContain('system.svg')
    expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).not.toContain('acme.svg')
    wrapper.unmount()
  })
})

it('offers keyboard-usable controls for every active theme component and preserves stored-only JSON', async () => {
  const { wrapper, calls } = await mountAt(page('theme'), '/t/acme/branding', () => ({ status: 200, body: { themeId: 'a', widget: { social_buttons_layout: 'bottom' } } }))
  await wrapper.find('#theme-colors-primary_button').setValue('#123456')
  await wrapper.find('#theme-fonts-title-size').setValue('125')
  await wrapper.find('#theme-fonts-title-bold').setValue('true')
  await wrapper.find('form').trigger('submit'); await flushPromises()
  expect(calls.find(c => c.method === 'PATCH')?.body).toEqual({ widget: { social_buttons_layout: 'bottom' }, colors: { primary_button: '#123456' }, fonts: { title: { size: 125, bold: true } } })
  expect(wrapper.findAll('fieldset input').length).toBeGreaterThan(20)
  expect(wrapper.find('#theme-widget-social_buttons_layout').exists()).toBe(false)
  wrapper.unmount()
})

it('acknowledges an empty-200 template save and restores that saved snapshot on Cancel', async () => {
 const { wrapper } = await mountAt(page('template'), '/t/acme/branding', c => c.method === 'GET' ? { status: 200, body: { template: '<p>A</p>' } } : { status: 200 })
 await wrapper.find('textarea').setValue('<p>B</p>'); await wrapper.find('form').trigger('submit'); await flushPromises()
 const editor = wrapper.findComponent(Editor)
 expect(editor.emitted('draft')?.at(-1)).toEqual([{ value: {}, invalid: false }])
 await wrapper.find('textarea').setValue('<p>C</p>')
 await wrapper.findAll('button').find(b => b.text() === 'Cancel')!.trigger('click')
 expect((wrapper.find('textarea').element as HTMLTextAreaElement).value).toBe('<p>B</p>')
 wrapper.unmount()
})
