import type { Connection, Job } from '../../api/client'
import { optionsOf } from '../connections/options'

// The server refuses a request body above 512000 bytes. The file travels
// inside a multipart body, so the console stops files that leave no room
// for that wrapping before it uploads anything.
export const SERVER_BODY_LIMIT = 512000
export const MAX_IMPORT_FILE_BYTES = 511000

// An export names at most this many fields.
export const MAX_EXPORT_FIELDS = 30

// The import guide's advice on weak password hashes and forcing a reset.
export const weakHashAdviceURL = 'https://github.com/zeroauthy/zeroauthy/blob/main/docs/user-import.md#weak-hashes'

export const POLL_MS = 3000

// The columns an export without fields writes, in order.
export const DEFAULT_EXPORT_FIELDS = [
  'user_id',
  'email',
  'name',
  'family_name',
  'given_name',
  'phone_number',
  'nickname',
  'username',
  'last_ip',
  'logins_count',
  'created_at',
  'updated_at',
  'deleted_at',
  'last_login',
  'blocked',
  'deleted',
  'email_verified',
  'phone_verified',
  'identities.[0].connection',
] as const

// importableConnections: database connections an import may target. A
// connection whose custom database scripts are the source of truth (custom
// database without import mode) is refused by the server, so it is not offered.
export function importableConnections(all: Connection[]): Connection[] {
  return all.filter((c) => {
    const o = optionsOf(c)
    return !(o.enabledDatabaseCustomization === true && o.import_mode !== true)
  })
}

export function isPending(j: Job): boolean {
  return j.status === 'pending'
}

// followLocation hands a download link to the browser, which saves the file
// without leaving the page.
export function followLocation(url: string): void {
  const a = document.createElement('a')
  a.href = url
  a.rel = 'noopener'
  a.click()
}
