import { describe, expect, it } from 'vitest'
import { mergeConfiguration, mergeOptions, unknownOptions } from './options'

describe('mergeOptions', () => {
  it('keeps every key it is not asked to change and removes undefined ones', () => {
    const cur = { a: 1, b: { x: 1 }, c: 'keep', d: 1 }
    expect(mergeOptions(cur, { a: 2, d: undefined })).toEqual({ a: 2, b: { x: 1 }, c: 'keep' })
    expect(cur.a).toBe(1)
  })
})

describe('mergeConfiguration', () => {
  it('sends blobs for untouched keys, plaintext for edited ones, and omits removed ones', () => {
    const cur = { A: 'zcv1.blobA', B: 'zcv1.blobB', C: null }
    expect(mergeConfiguration(cur, { B: 'new', D: 'added' }, ['C'])).toEqual({ A: 'zcv1.blobA', B: 'new', D: 'added' })
  })
})

describe('mergeConfiguration re-added keys', () => {
  it('applies removed to the current keys only, never to new plaintext', () => {
    expect(mergeConfiguration({ A: 'zcv1.blobA' }, { A: 'again' }, ['A'])).toEqual({ A: 'again' })
  })
})

describe('unknownOptions', () => {
  it('lists the keys no control owns', () => {
    expect(unknownOptions({ brute_force_protection: true, mfa: {}, strategy_version: 2, zzz: 1 })).toEqual({ strategy_version: 2, zzz: 1 })
  })
})
