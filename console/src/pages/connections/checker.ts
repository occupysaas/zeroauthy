// A TypeScript port of the server's password checks (internal/identity),
// for the live checker in the password policy tab. It runs in the browser
// and the sample password goes nowhere. Not ported, because they need data
// only the server has: the embedded common-password lists (en_10k, en_100k)
// and the user's password history.

export const CHARACTER_TYPES = ['lowercase', 'uppercase', 'number', 'special'] as const
export type CharacterType = (typeof CHARACTER_TYPES)[number]

// MAX_PASSWORD_BYTES is the longest password zeroauthy hashes.
export const MAX_PASSWORD_BYTES = 72
// MIN_PROFILE_VALUE is the shortest profile value the personal data rule
// looks for.
export const MIN_PROFILE_VALUE = 3

export interface Policy {
  minLength: number
  characterTypes: string[]
  characterTypeRule: 'all' | 'three_of_four'
  identical: 'allow' | 'block'
  sequential: 'allow' | 'block'
  maxLengthExceeded: 'error' | 'truncate'
  dictionaryActive: boolean
  customWords: string[]
  profileActive: boolean
  blockedFields: string[]
}

// Profile is the sample profile fields the operator types.
export interface Profile {
  name: string
  username: string
  nickname: string
  email: string
  phone_number: string
  user_metadata_name: string
  user_metadata_first: string
  user_metadata_last: string
}

export const emptyProfile = (): Profile => ({
  name: '',
  username: '',
  nickname: '',
  email: '',
  phone_number: '',
  user_metadata_name: '',
  user_metadata_first: '',
  user_metadata_last: '',
})

export type RuleID = 'length' | 'types' | 'identical' | 'sequential' | 'dictionary' | 'personal'

export interface RuleResult {
  rule: RuleID
  // checked is false when the rule is off, or cannot run in the browser.
  checked: boolean
  ok: boolean
  // detail carries a number or list for the message (the minimum length,
  // the character types missing).
  detail?: string
}

const encoder = new TextEncoder()

export function byteLength(s: string): number {
  return encoder.encode(s).length
}

// effectivePassword is the password as the server hashes it: with
// max_length_exceeded "truncate", one longer than 72 bytes is cut at 72
// bytes, never inside a character.
export function effectivePassword(p: Policy, password: string): string {
  if (p.maxLengthExceeded !== 'truncate' || byteLength(password) <= MAX_PASSWORD_BYTES) return password
  let out = ''
  let n = 0
  for (const ch of password) {
    const b = byteLength(ch)
    if (n + b > MAX_PASSWORD_BYTES) break
    out += ch
    n += b
  }
  return out
}

// fold approximates the server's NFC plus case folding.
export function fold(s: string): string {
  return s.normalize('NFC').toLowerCase().replace(/ß/g, 'ss')
}

export function hasIdentical(s: string): boolean {
  let prev = ''
  let run = 0
  for (const ch of s) {
    run = run > 0 && ch === prev ? run + 1 : 1
    if (run >= 3) return true
    prev = ch
  }
  return false
}

function seqClass(ch: string): string {
  if (ch >= '0' && ch <= '9') return 'd'
  if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')) return 'a'
  return ''
}

// hasSequential reports three or more ASCII letters (any case) or digits in
// a row, each one after the last, ascending or descending.
export function hasSequential(s: string): boolean {
  let prev = ''
  let step = 0
  let run = 1
  for (const raw of s) {
    const ch = raw.toLowerCase()
    const d = prev === '' ? 0 : ch.codePointAt(0)! - prev.codePointAt(0)!
    if (prev !== '' && (d === 1 || d === -1) && seqClass(ch) !== '' && seqClass(ch) === seqClass(prev)) {
      if (step === d) run++
      else {
        step = d
        run = 2
      }
    } else {
      step = 0
      run = 1
    }
    if (run >= 3) return true
    prev = ch
  }
  return false
}

// classesOf is which of the four character types the password holds.
export function classesOf(password: string): Set<CharacterType> {
  const has = new Set<CharacterType>()
  for (const ch of password) {
    if (/\p{Ll}/u.test(ch)) has.add('lowercase')
    else if (/\p{Lu}/u.test(ch)) has.add('uppercase')
    else if (/\p{Nd}/u.test(ch)) has.add('number')
    else has.add('special')
  }
  return has
}

function checkTypes(p: Policy, password: string): RuleResult {
  if (p.characterTypes.length === 0) return { rule: 'types', checked: false, ok: true }
  const has = classesOf(password)
  if (p.characterTypeRule === 'three_of_four') {
    return { rule: 'types', checked: true, ok: has.size >= 3, detail: '3' }
  }
  const missing = CHARACTER_TYPES.filter((t) => p.characterTypes.includes(t) && !has.has(t))
  return { rule: 'types', checked: true, ok: missing.length === 0, detail: missing.join(',') }
}

// profileValues are the values of the blocked fields the sample profile has.
export function profileValues(blocked: string[], prof: Profile): string[] {
  const out: string[] = []
  for (const f of blocked) {
    switch (f) {
      case 'name':
        out.push(prof.name)
        break
      case 'username':
        out.push(prof.username)
        break
      case 'nickname':
        out.push(prof.nickname)
        break
      case 'email': {
        out.push(prof.email)
        const at = prof.email.indexOf('@')
        if (at >= 0) out.push(prof.email.slice(0, at))
        break
      }
      case 'phone_number':
        out.push(prof.phone_number)
        break
      case 'user_metadata.name':
        out.push(prof.user_metadata_name)
        break
      case 'user_metadata.first':
        out.push(prof.user_metadata_first)
        break
      case 'user_metadata.last':
        out.push(prof.user_metadata_last)
        break
    }
  }
  return out
}

export function hasPersonalInfo(blocked: string[], prof: Profile, candidate: string): boolean {
  const folded = fold(candidate)
  for (const raw of profileValues(blocked, prof)) {
    const v = raw.trim()
    if ([...v].length < MIN_PROFILE_VALUE) continue
    if (folded.includes(fold(v))) return true
  }
  return false
}

// checkPassword runs the rules in the server's order and returns one result
// per rule. The first three are complexity, which stops at its first
// failure on the server; here every rule is reported so the operator sees
// them all.
export function checkPassword(p: Policy, prof: Profile, password: string): RuleResult[] {
  const candidate = effectivePassword(p, password)
  const results: RuleResult[] = []

  const tooLong = byteLength(candidate) > MAX_PASSWORD_BYTES
  const minLen = p.minLength > 0 ? p.minLength : 8
  const short = [...candidate].length < minLen
  results.push({ rule: 'length', checked: true, ok: !tooLong && !short, detail: tooLong ? 'long' : String(minLen) })
  results.push(checkTypes(p, candidate))
  results.push({ rule: 'identical', checked: p.identical === 'block', ok: !(p.identical === 'block' && hasIdentical(candidate)) })
  results.push({ rule: 'sequential', checked: p.sequential === 'block', ok: !(p.sequential === 'block' && hasSequential(candidate)) })

  const folded = fold(candidate)
  const custom = p.customWords.map((w) => w.trim()).filter(Boolean)
  results.push({
    rule: 'dictionary',
    checked: p.dictionaryActive,
    ok: !(p.dictionaryActive && custom.some((w) => fold(w) === folded)),
  })
  results.push({ rule: 'personal', checked: p.profileActive, ok: !(p.profileActive && hasPersonalInfo(p.blockedFields, prof, candidate)) })
  return results
}
