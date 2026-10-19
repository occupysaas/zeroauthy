import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const src = resolve(process.cwd(), 'src')

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]))
}

const files = walk(src)
const vue = files.filter((f) => f.endsWith('.vue'))
const rel = (f: string) => f.slice(src.length + 1)

describe('styling', () => {
  it('has no scoped style blocks in any component', () => {
    const offenders = vue.filter((f) => readFileSync(f, 'utf8').includes('<style')).map(rel)
    expect(offenders).toEqual([])
  })

  it('uses none of the legacy CSS variables', () => {
    const legacy = /var\(--(border|accent-soft|surface-2|text-2)\)/
    const offenders = files.filter((f) => /\.(vue|css|ts)$/.test(f) && !f.endsWith('nostyle.test.ts') && legacy.test(readFileSync(f, 'utf8'))).map(rel)
    expect(offenders).toEqual([])
  })
})
