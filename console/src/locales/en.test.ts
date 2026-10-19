import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createConsoleI18n } from '../i18n'
import en from './en'

type Leaf = { key: string; text: string }
function leaves(node: unknown, prefix: string, out: Leaf[] = []): Leaf[] {
  if (typeof node === 'string') out.push({ key: prefix, text: node })
  else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) leaves(v, prefix ? prefix + '.' + k : k, out)
  }
  return out
}

const i18n = createConsoleI18n('en')
const all = leaves(en, '')
const names = ['from', 'to', 'total', 'name', 'mode', 'values', 'grants', 'seconds', 'n', 'key', 'ms', 'audience', 'what', 'email', 'confirmWith', 'when', 'apis']

describe('English catalog', () => {
  it('has strings', () => {
    expect(all.length).toBeGreaterThan(300)
  })

  it('renders every key without throwing or leaving syntax behind', () => {
    // Every named placeholder is filled, so only broken syntax can leave a brace.
    const named = Object.fromEntries(names.map((k) => [k, 'x']))
    for (const { key, text } of all) {
      const out = i18n.global.t(key, named) as string
      expect({ key, braces: /[{}]/.test(out) }).toEqual({ key, braces: false })
      if (text !== '') expect(out).not.toBe('')
    }
  })

  it('renders text without placeholders exactly as written', () => {
    // vue-i18n syntax characters (| @ $) in English must stay literal.
    for (const { key, text } of all.filter((l) => !l.text.includes('{'))) {
      expect({ key, out: i18n.global.t(key) }).toEqual({ key, out: text })
    }
  })

  it('has every key the source asks for by a literal', () => {
    const files: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name)
        if (statSync(p).isDirectory()) walk(p)
        else if (/\.(vue|ts)$/.test(name) && !/\.test\.ts$|\.d\.ts$/.test(name)) files.push(p)
      }
    }
    walk(join(__dirname, '..'))
    const known = new Set(all.map((l) => l.key))
    // vue-i18n's own types accept any string, so a typo is caught here.
    const missing: string[] = []
    for (const f of files) {
      for (const m of readFileSync(f, 'utf8').matchAll(/\bt\('([A-Za-z][\w.]*)'/g)) {
        if (!known.has(m[1]!)) missing.push(`${f}: ${m[1]}`)
      }
    }
    expect(missing).toEqual([])
  })
})
