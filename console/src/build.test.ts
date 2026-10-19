import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// vitest runs from console/, where the built bundle lives.
const dist = join(process.cwd(), 'dist')
const built = existsSync(join(dist, 'index.html'))
if (!built) console.warn('dist/ is absent: run `npm run build` to enable the bundle checks')

describe.skipIf(!built)('built bundle', () => {
  const assets = built ? readdirSync(join(dist, 'assets')) : []
  const text = assets
    .filter((f) => /\.(js|css)$/.test(f))
    .map((f) => ({ f, s: readFileSync(join(dist, 'assets', f), 'utf8') }))

  it('has no inline style in index.html', () => {
    expect(readFileSync(join(dist, 'index.html'), 'utf8')).not.toContain('<style')
  })

  it('has no eval or new Function in scripts', () => {
    for (const { f, s } of text.filter((t) => t.f.endsWith('.js'))) {
      expect(s, f).not.toContain('new Function(')
      expect(s, f).not.toContain('eval(')
    }
  })

  it('loads fonts only from the bundle', () => {
    for (const { f, s } of text.filter((t) => t.f.endsWith('.css'))) {
      expect(s, f).not.toMatch(/fonts\.googleapis|cdnfonts/)
      expect(s, f).not.toMatch(/url\(\s*["']?https?:/)
    }
  })

  it('ships a woff2 font', () => {
    expect(assets.some((f) => f.endsWith('.woff2'))).toBe(true)
  })
})
