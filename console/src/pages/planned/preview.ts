import type { VueWrapper } from '@vue/test-utils'

/** Test helper: every control outside the live in-page navigation is disabled. */
export function assertPreviewInert(wrapper: VueWrapper): void {
  const controls = wrapper.element.querySelectorAll('button, input, select, textarea, [role=switch]')
  for (const el of controls) {
    if (el.closest('[data-preview-nav]')) continue
    const inert = (el as HTMLButtonElement).disabled || el.getAttribute('aria-disabled') === 'true' || el.hasAttribute('data-disabled')
    if (!inert) throw new Error(`preview control is not disabled: ${el.outerHTML}`)
  }
}
