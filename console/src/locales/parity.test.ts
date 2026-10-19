import { describe, expect, it } from 'vitest'
import { locales } from '../i18n'
import en from './en'

function keys(node: unknown, prefix = '', out: string[] = []): string[] {
  if (typeof node === 'string') out.push(prefix)
  else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) keys(v, prefix ? prefix + '.' + k : k, out)
  }
  return out.sort()
}

// Every catalog file in this directory (tests excluded), found by glob so a
// second language is checked without editing this test.
const catalogs = import.meta.glob<{ default: unknown }>(['./*.ts', '!./*.test.ts'], { eager: true })

describe('locale catalogs', () => {
  it('finds the English catalog', () => {
    expect(Object.keys(catalogs)).toContain('./en.ts')
  })

  it('has a catalog for every listed locale and none unlisted', () => {
    expect(Object.keys(catalogs).map((f) => f.slice(2, -3)).sort()).toEqual(locales.map((l) => l.code).sort())
  })

  it.each(locales.filter((l) => l.code !== 'en').map((l) => l.code))('%s has exactly the English keys', (code) => {
    expect(keys(catalogs[`./${code}.ts`].default)).toEqual(keys(en))
  })
})
