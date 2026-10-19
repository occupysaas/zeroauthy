import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(resolve(process.cwd(), 'src/ui/app.css'), 'utf8')

describe('app.css', () => {
  it('has the three theme blocks', () => {
    expect(css).toContain(':root {')
    expect(css).toContain('@media (prefers-color-scheme: dark)')
    expect(css).toContain(":root:not([data-theme='light'])")
    expect(css).toContain(":root[data-theme='dark']")
  })

  it('uses the brand palette', () => {
    expect(css).toContain('--accent: #d7141a')
    expect(css).toContain('--bg: #ffffff')
    expect(css).toContain('--bg: #121212')
    expect(css).toContain('--accent: #ff3b40')
  })

  it('has no off-white and no remote URLs', () => {
    expect(css.toLowerCase()).not.toContain('f5f2eb')
    expect(css).not.toMatch(/https?:\/\//)
  })

  it('declares Glacial Indifference 400 and 700 with swap', () => {
    const faces = css.match(/@font-face\s*{[^}]*}/g) ?? []
    expect(faces).toHaveLength(2)
    for (const weight of ['400', '700']) {
      const face = faces.find((f) => new RegExp(`font-weight:\\s*${weight}\\b`).test(f))
      expect(face, `weight ${weight}`).toBeDefined()
      expect(face).toContain('font-display: swap')
    }
  })
})
