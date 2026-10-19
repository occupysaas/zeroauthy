import { createI18n, type I18n } from 'vue-i18n'
import en from './locales/en'

// The languages the console is translated into.
export const locales = [{ code: 'en', name: 'English' }] as const

export type Locale = (typeof locales)[number]['code']

// The Composition API flavour of vue-i18n's instance, which the console uses.
export type ConsoleI18n = I18n<Record<string, never>, Record<string, never>, Record<string, never>, string, false>

const KEY = 'zeroauthy.console.locale'

function supported(code: string | null | undefined): Locale | null {
  const primary = (code ?? '').toLowerCase().split('-')[0]
  return locales.find((l) => l.code === primary)?.code ?? null
}

// The newest instance, which the preferences store switches when the
// operator picks a language.
let current: ConsoleI18n | null = null

// activeI18n is the instance createConsoleI18n made last, if any.
export function activeI18n(): ConsoleI18n | null {
  return current
}

// createConsoleI18n makes the vue-i18n instance, starting in locale.
export function createConsoleI18n(locale: Locale): ConsoleI18n {
  const quiet = import.meta.env.PROD
  current = createI18n({
    legacy: false,
    locale,
    fallbackLocale: 'en',
    missingWarn: !quiet,
    fallbackWarn: !quiet,
    messages: { en },
  })
  return current
}

// savedLocale is the operator's saved choice, else the browser's first
// supported language, else English. Storage may be unavailable.
export function savedLocale(): Locale {
  try {
    const v = supported(window.localStorage.getItem(KEY))
    if (v) return v
  } catch {
    // Fall through to the browser's languages.
  }
  for (const l of navigator.languages ?? []) {
    const v = supported(l)
    if (v) return v
  }
  return 'en'
}

// applyLocale switches the instance to l and marks the page's language. It
// does not remember anything: startup uses it with the detected locale.
export function applyLocale(i18n: ConsoleI18n, l: Locale): void {
  i18n.global.locale.value = l
  document.documentElement.lang = l
}

// rememberLocale saves the operator's explicit choice.
export function rememberLocale(l: Locale): void {
  try {
    window.localStorage.setItem(KEY, l)
  } catch {
    // Storage may be unavailable; the language still applies to this page.
  }
}
