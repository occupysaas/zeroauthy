import type { Api, SystemTenant } from '../../api/client'
export type Values = Record<string, unknown>
export interface PolicyField {
  path: string
  label: string
  kind?: 'number' | 'toggle' | 'lines' | 'password' | 'email' | 'url'
  options?: string[]
  hint?: string
  min?: number
  max?: number
  readonly?: boolean
}
export interface Panel {
  key: string
  title: string
  fields: PolicyField[]
  hint?: string
  load: (api: Api, tenant: SystemTenant) => Promise<Values>
  save: (api: Api, tenant: SystemTenant, patch: Values) => Promise<Values>
  captcha?: boolean
}
export const field = (path: string, kind?: PolicyField['kind'], extra: Partial<PolicyField> = {}): PolicyField => ({ path, label: 'policy.fields.' + path.replaceAll('.', '_').replaceAll('-', '_'), kind, ...extra })
export function read(data: Values, path: string): unknown {
  return path.split('.').reduce<unknown>((value, key) => value && typeof value === 'object' ? (value as Values)[key] : undefined, data)
}
export function put(data: Values, path: string, value: unknown) {
  const keys = path.split('.')
  let current = data
  for (const key of keys.slice(0, -1)) current = (current[key] ??= {}) as Values
  current[keys.at(-1)!] = value
}
export const providers = ['recaptcha_v2', 'recaptcha_enterprise', 'hcaptcha', 'friendly_captcha', 'arkose', 'auth_challenge', 'simple_captcha']
// Never copy response objects into a PATCH: only edited fields belong there.
export function patchFor(fields: PolicyField[], original: Values, draft: Values, captcha = false): Values {
  const patch: Values = {}
  for (const f of fields) {
    if (f.readonly) continue
    const value = draft[f.path]
    if (f.kind === 'password' && !value) continue
    if (JSON.stringify(value) === JSON.stringify(original[f.path])) continue
    put(patch, f.path, f.kind === 'lines' ? String(value ?? '').split('\n').map(x => x.trim()).filter(Boolean) : value)
  }
  if (captcha) {
    for (const provider of providers) {
      if (!patch[provider]) continue
      const values = patch[provider] as Values
      // Supplied provider objects require all children, including a new secret.
      for (const f of fields.filter(f => f.path.startsWith(provider + '.'))) {
        values[f.path.split('.')[1]!] = draft[f.path]
      }
    }
  }
  return patch
}
