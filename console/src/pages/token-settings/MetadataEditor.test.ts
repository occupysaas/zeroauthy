import { mount, flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { createConsoleI18n } from '../../i18n'
import MetadataEditor from './MetadataEditor.vue'
import { confirmPrompt, topDialog } from '../../test/mount'
afterEach(() => { document.body.innerHTML = '' })
it('validates metadata bounds before save and sends an empty object to clear', async () => {
  const writes: Record<string, string>[] = []
  const wrapper = mount(MetadataEditor, { props: { id: 'rt1', metadata: { label: 'browser' }, save: async value => { writes.push(value) } }, attachTo: document.body, global: { plugins: [createConsoleI18n('en')] } })
  await wrapper.get('[data-testid=metadata-rt1]').trigger('click'); await flushPromises()
  const input = () => topDialog()!.querySelector<HTMLTextAreaElement>('textarea')!
  const fill = async (value: unknown) => { input().value = JSON.stringify(value); input().dispatchEvent(new Event('input')); await flushPromises(); await confirmPrompt() }
  for (const value of [{ label: 1 }, Object.fromEntries(Array.from({ length: 26 }, (_, i) => ['k'+i, 'v'])), { ['k'.repeat(256)]: 'v' }, { label: 'v'.repeat(256) }]) {
    await fill(value)
    expect(writes).toHaveLength(0)
    expect(topDialog()?.textContent).toContain('at most 25 string properties')
  }
  await fill({ emoji: '💠'.repeat(255), empty: '' })
  expect(writes).toEqual([{ emoji: '💠'.repeat(255), empty: '' }])
  await wrapper.get('[data-testid=metadata-rt1]').trigger('click'); await flushPromises()
  await fill({})
  expect(writes.at(-1)).toEqual({})
  wrapper.unmount()
})
