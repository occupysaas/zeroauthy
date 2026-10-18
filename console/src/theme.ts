// The colour theme: the system's, or one the operator picked. The choice
// is a per-browser convenience, so it may be lost.

export type Theme = 'system' | 'light' | 'dark'

const KEY = 'zeroauthy.console.theme'

export function savedTheme(): Theme {
  try {
    const v = window.localStorage.getItem(KEY)
    return v === 'light' || v === 'dark' ? v : 'system'
  } catch {
    return 'system'
  }
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  if (theme === 'system') delete root.dataset.theme
  else root.dataset.theme = theme
  try {
    if (theme === 'system') window.localStorage.removeItem(KEY)
    else window.localStorage.setItem(KEY, theme)
  } catch {
    // Storage may be unavailable; the theme still applies to this page.
  }
}
