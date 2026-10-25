import { describe, expect, it } from 'vitest'
import en from '../locales/en'
import { routes } from '../router'
import { isPlanned, plannedWhenKey, sections, visibleSections } from './sections'

function lookup(key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], en)
}

describe('sections', () => {
  it('has a route for every section', () => {
    const names = new Set(routes.map((r) => r.name))
    for (const s of sections) expect(names.has(s.key), s.key).toBe(true)
  })

  it('has a section for every tenant route that is not a form, a detail page or a sub page', () => {
    const keys = new Set(sections.map((s) => s.key))
    const missing = routes
      .filter((r) => r.path.startsWith('/t/:tenant/') && !String(r.name).endsWith('-new') && !r.path.includes('/:id') && !r.path.slice('/t/:tenant/'.length).includes('/'))
      .filter((r) => !keys.has(String(r.name)))
    expect(missing).toEqual([])
  })

  it('has unique keys', () => {
    const keys = sections.map((s) => s.key)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it('ships tenant email configuration as a live section', () => {
    expect(sections.find((s) => s.key === 'emails')?.status).toBe('live')
    expect(routes.find((r) => r.name === 'emails')?.path).toBe('/t/:tenant/emails')
  })

  it('hides Operators outside the system tenant and lists it last inside', () => {
    expect(visibleSections(false).map((s) => s.key)).not.toContain('operators')
    expect(visibleSections(true).at(-1)?.key).toBe('operators')
  })

  it('has a catalog string for every label and group', () => {
    for (const s of sections) {
      expect(typeof lookup(s.label), s.label).toBe('string')
      if (s.group) expect(typeof lookup(s.group), s.group).toBe('string')
    }
  })

  it('has a catalog string for every planned-when value', () => {
    for (const s of sections.filter(isPlanned)) expect(typeof lookup(plannedWhenKey(s.status)), s.key).toBe('string')
  })

  it('names the APIs of every planned section', () => {
    for (const s of sections.filter(isPlanned)) expect(s.status.api.length, s.key).toBeGreaterThan(0)
  })
})
