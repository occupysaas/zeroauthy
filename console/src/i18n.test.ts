import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { applyLocale, createConsoleI18n, rememberLocale, savedLocale } from './i18n'

const KEY = 'zeroauthy.console.locale'

function languages(list: string[]) {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(list)
}

beforeEach(() => window.localStorage.clear())
afterEach(() => vi.restoreAllMocks())

describe('savedLocale', () => {
  it('prefers the stored choice over the browser', () => {
    window.localStorage.setItem(KEY, 'en')
    languages(['fr-FR'])
    expect(savedLocale()).toBe('en')
  })

  it('matches a browser language by its primary subtag', () => {
    languages(['fr-FR', 'en-GB'])
    expect(savedLocale()).toBe('en')
  })

  it('falls back to English when nothing matches', () => {
    languages(['fr-FR'])
    expect(savedLocale()).toBe('en')
  })

  it('falls back to the browser when storage throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    languages(['en-US'])
    expect(savedLocale()).toBe('en')
  })
})

describe('startup and remembering', () => {
  it('applyLocale sets the language without saving it', () => {
    const i18n = createConsoleI18n('en')
    applyLocale(i18n, 'en')
    expect(document.documentElement.lang).toBe('en')
    expect(window.localStorage.getItem(KEY)).toBeNull()
  })

  it('rememberLocale saves, and tolerates unavailable storage', () => {
    rememberLocale('en')
    expect(window.localStorage.getItem(KEY)).toBe('en')
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    expect(() => rememberLocale('en')).not.toThrow()
  })
})
