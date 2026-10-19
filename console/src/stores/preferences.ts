import { defineStore } from 'pinia'
import { applyTheme, savedTheme, type Theme } from '../theme'

// Per-browser conveniences: the colour theme and the display language.
export const usePreferencesStore = defineStore('preferences', {
  state: () => ({
    theme: savedTheme() as Theme,
    locale: 'en',
  }),
  actions: {
    setTheme(t: Theme): void {
      this.theme = t
      applyTheme(t)
    },

    // setLocale only remembers the language until the i18n instance is wired.
    setLocale(l: string): void {
      this.locale = l
    },
  },
})
