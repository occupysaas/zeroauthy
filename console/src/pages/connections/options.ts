import type { Connection } from '../../api/client'

// A connection's options are replaced whole by PATCH (decision D-0042), so
// every save sends the complete object: the options of the last GET with
// the edited parts replaced. These helpers build that object.

export type Options = Record<string, unknown>

export const SCRIPT_NAMES = ['login', 'get_user', 'create', 'verify', 'change_password', 'delete', 'change_email'] as const

// The option keys a tab edits and zeroauthy enforces.
export const ENFORCED_KEYS = [
  'password_options',
  'brute_force_protection',
  'disable_signup',
  'requires_username',
  'validation',
  'enabledDatabaseCustomization',
  'import_mode',
  'customScripts',
  'configuration',
  'set_user_root_attributes',
] as const

// The option keys zeroauthy stores without enforcing (D-0042).
export const STORED_KEYS = [
  'authentication_methods',
  'passkey_options',
  'attributes',
  'precedence',
  'mfa',
  'disable_self_service_change_password',
  'non_persistent_attrs',
] as const

export function optionsOf(c: Connection): Options {
  return { ...((c.options as Options | undefined) ?? {}) }
}

// unknownOptions are the option keys the console has no control for. They
// are shown read-only and travel back unchanged on every save.
export function unknownOptions(options: Options): Options {
  const known = new Set<string>([...ENFORCED_KEYS, ...STORED_KEYS])
  return Object.fromEntries(Object.entries(options).filter(([k]) => !known.has(k)))
}

// mergeOptions is current with edits laid over it: a key set to undefined is
// removed, every other key of current stays as it was.
export function mergeOptions(current: Options, edits: Options): Options {
  const out: Options = { ...current }
  for (const [k, v] of Object.entries(edits)) {
    if (v === undefined) delete out[k]
    else out[k] = v
  }
  return out
}

// mergeConfiguration builds options.configuration: the opaque blob the API
// returned for every key the operator did not touch, the plaintext of the
// ones they set (new or replaced), and nothing for the ones they removed.
export function mergeConfiguration(current: Record<string, string | null> | undefined, replaced: Record<string, string>, removed: string[]): Record<string, string | null> {
  const out: Record<string, string | null> = {}
  for (const [k, v] of Object.entries(current ?? {})) {
    if (!removed.includes(k)) out[k] = v
  }
  for (const [k, v] of Object.entries(replaced)) {
    out[k] = v
  }
  return out
}

export function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

export function asStrings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

export function pretty(v: unknown): string {
  return JSON.stringify(v, null, 2)
}

// parseJSON parses a textarea that must hold an object (or, with array,
// an array); it returns null when it does not.
export function parseJSON(text: string, kind: 'object' | 'array'): unknown | null {
  try {
    const v = JSON.parse(text) as unknown
    if (kind === 'array') return Array.isArray(v) ? v : null
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null
  } catch {
    return null
  }
}
