import { defineStore } from 'pinia'
import { activeI18n, applyLocale, savedLocale, type Locale } from '../i18n'
import { applyTheme, savedTheme, type Theme } from '../theme'

// Per-browser conveniences: the colour theme and the display language.
export const usePreferencesStore = defineStore('preferences', {
  state: () => ({
    theme: savedTheme() as Theme,
    locale: savedLocale() as Locale,
  }),
  actions: {
    setTheme(t: Theme): void {
      this.theme = t
      applyTheme(t)
    },

    setLocale(l: Locale): void {
      this.locale = l
      const i18n = activeI18n()
      if (i18n) applyLocale(i18n, l)
    },
  },
})
