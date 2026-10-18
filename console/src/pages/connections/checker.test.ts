import { describe, expect, it } from 'vitest'
import { checkPassword, effectivePassword, emptyProfile, hasIdentical, hasSequential, type Policy, type Profile, type RuleID } from './checker'

const base: Policy = {
  minLength: 8,
  characterTypes: [],
  characterTypeRule: 'all',
  identical: 'allow',
  sequential: 'allow',
  maxLengthExceeded: 'error',
  dictionaryActive: false,
  customWords: [],
  profileActive: false,
  blockedFields: ['name', 'email', 'username', 'user_metadata.first'],
}

function result(p: Partial<Policy>, pw: string, rule: RuleID, prof: Partial<Profile> = {}) {
  return checkPassword({ ...base, ...p }, { ...emptyProfile(), ...prof }, pw).find((r) => r.rule === rule)!
}

describe('length', () => {
  it('counts characters, not bytes', () => {
    expect(result({ minLength: 5 }, 'abcd', 'length').ok).toBe(false)
    expect(result({ minLength: 5 }, 'abcde', 'length').ok).toBe(true)
    expect(result({ minLength: 4 }, 'éééé', 'length').ok).toBe(true)
  })
  it('refuses more than 72 bytes, or cuts them when truncating', () => {
    const long = 'a'.repeat(73)
    expect(result({}, long, 'length')).toMatchObject({ ok: false, detail: 'long' })
    expect(result({ maxLengthExceeded: 'truncate' }, long, 'length').ok).toBe(true)
    expect(effectivePassword({ ...base, maxLengthExceeded: 'truncate' }, 'é'.repeat(37))).toBe('é'.repeat(36))
  })
})

describe('character types', () => {
  it('is not checked with no types listed', () => {
    expect(result({}, 'x', 'types').checked).toBe(false)
  })
  it('rule all needs every listed type, and names what is missing', () => {
    const p = { characterTypes: ['lowercase', 'number', 'special'] }
    expect(result(p, 'abc123', 'types')).toMatchObject({ ok: false, detail: 'special' })
    expect(result(p, 'abc123!', 'types').ok).toBe(true)
  })
  it('rule three_of_four needs any three classes', () => {
    const p = { characterTypes: ['lowercase', 'uppercase', 'number', 'special'], characterTypeRule: 'three_of_four' as const }
    expect(result(p, 'abcDEF', 'types').ok).toBe(false)
    expect(result(p, 'abcDEF1', 'types').ok).toBe(true)
    expect(result(p, 'abc 123', 'types').ok).toBe(true)
  })
})

describe('identical and sequential blocks', () => {
  it('finds three identical characters in a row', () => {
    expect(hasIdentical('aab')).toBe(false)
    expect(hasIdentical('xaaay')).toBe(true)
    expect(result({ identical: 'block' }, 'baaad', 'identical').ok).toBe(false)
    expect(result({ identical: 'allow' }, 'baaad', 'identical')).toMatchObject({ checked: false, ok: true })
  })
  it('finds ascending and descending runs of letters or digits', () => {
    for (const s of ['abc', 'xCBa', '123', '9870', 'ABc']) expect(hasSequential(s), s).toBe(true)
    for (const s of ['abd', '1a2', 'a9:', 'ac', '']) expect(hasSequential(s), s).toBe(false)
    expect(result({ sequential: 'block' }, 'q321w', 'sequential').ok).toBe(false)
    expect(result({ sequential: 'block' }, 'q3w2e1', 'sequential').ok).toBe(true)
  })
})

describe('custom dictionary', () => {
  it('compares your own words without regard to case', () => {
    const p = { dictionaryActive: true, customWords: ['Acme2026', ' secret '] }
    expect(result(p, 'ACME2026', 'dictionary').ok).toBe(false)
    expect(result(p, 'Secret', 'dictionary').ok).toBe(false)
    expect(result(p, 'acme2026x', 'dictionary').ok).toBe(true)
    expect(result({ ...p, dictionaryActive: false }, 'acme2026', 'dictionary').checked).toBe(false)
  })
})

describe('personal data', () => {
  const p = { profileActive: true }
  it('refuses a password containing a blocked field value', () => {
    expect(result(p, 'xxJordanxx', 'personal', { name: 'jordan' }).ok).toBe(false)
    expect(result(p, 'my-Jo-pw', 'personal', { name: 'Jordan' }).ok).toBe(true)
  })
  it('uses the local part of an email, and only fields that are blocked', () => {
    expect(result(p, 'sam.smith99', 'personal', { email: 'Sam.Smith@example.com' }).ok).toBe(false)
    expect(result(p, 'nicknamekit', 'personal', { nickname: 'nicknamekit' }).ok).toBe(true)
    expect(result(p, 'ada-lovelace', 'personal', { user_metadata_first: 'Ada' }).ok).toBe(false)
  })
  it('ignores values shorter than three characters, and is off when inactive', () => {
    expect(result(p, 'abxy', 'personal', { name: 'ab' }).ok).toBe(true)
    expect(result({ profileActive: false }, 'jordan', 'personal', { name: 'jordan' }).checked).toBe(false)
  })
})

describe('what only the server can check', () => {
  it('has no result for history or the built-in lists', () => {
    const ids = checkPassword(base, emptyProfile(), 'password').map((r) => r.rule)
    expect(ids).not.toContain('history')
    expect(ids).not.toContain('common')
  })
})
