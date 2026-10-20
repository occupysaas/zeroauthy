import type { Connection } from '../../api/client'
import type { Policy } from '../connections/checker'
import { asRecord, asStrings, optionsOf } from '../connections/options'

// policyOf reads a connection's password_options as the live checker's
// policy, with the defaults the server uses for what is absent.
export function policyOf(c: Connection | undefined): Policy {
  const po = asRecord(optionsOf(c ?? ({} as Connection)).password_options)
  const cx = asRecord(po.complexity)
  const d = asRecord(po.dictionary)
  const p = asRecord(po.profile_data)
  return {
    minLength: typeof cx.min_length === 'number' ? cx.min_length : 8,
    characterTypes: asStrings(cx.character_types),
    characterTypeRule: cx.character_type_rule === 'three_of_four' ? 'three_of_four' : 'all',
    identical: cx.identical_characters === 'block' ? 'block' : 'allow',
    sequential: cx.sequential_characters === 'block' ? 'block' : 'allow',
    maxLengthExceeded: cx.max_length_exceeded === 'truncate' ? 'truncate' : 'error',
    dictionaryActive: d.active === true,
    customWords: asStrings(d.custom).map((w) => w.trim()).filter(Boolean),
    profileActive: p.active === true,
    blockedFields: Array.isArray(p.blocked_fields) ? asStrings(p.blocked_fields) : [],
  }
}

// requiresUsername is whether the connection asks users for a username.
export function requiresUsername(c: Connection | undefined): boolean {
  return c !== undefined && optionsOf(c).requires_username === true
}

// relativeTime says how long ago an instant was ("3 days ago"), in locale.
export function relativeTime(iso: string, now: number, locale: string): string {
  const ms = Date.parse(iso) - now
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 31536000000],
    ['month', 2592000000],
    ['day', 86400000],
    ['hour', 3600000],
    ['minute', 60000],
  ]
  const fmt = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' })
  for (const [unit, size] of units) {
    if (Math.abs(ms) >= size) return fmt.format(Math.round(ms / size), unit)
  }
  return fmt.format(0, 'second')
}

// formatTime shows an instant in the reader's locale.
export function formatTime(iso: string, locale: string): string {
  return new Date(iso).toLocaleString(locale)
}
