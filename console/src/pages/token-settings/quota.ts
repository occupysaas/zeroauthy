export interface Quota { client_credentials: { enforce?: boolean; per_hour?: number; per_day?: number } }
export interface QuotaDraft { enabled: boolean; enforce: boolean; hour: string; day: string }
export function quotaDraft(value?: Quota | null): QuotaDraft {
  return { enabled: !!value, enforce: value?.client_credentials.enforce !== false, hour: String(value?.client_credentials.per_hour ?? ''), day: String(value?.client_credentials.per_day ?? '') }
}
export function quotaValue(d: QuotaDraft): Quota | null {
  if (!d.enabled) return null
  const q: Quota['client_credentials'] = { enforce: d.enforce }
  for (const [field, text] of [['per_hour', d.hour], ['per_day', d.day]] as const) {
    if (!text.trim()) continue
    if (!/^\d+$/.test(text.trim()) || Number(text) < 1 || Number(text) > 2147483647) throw new Error('Enter a whole-number quota from 1 to 2147483647.')
    q[field] = Number(text)
  }
  if (!q.per_hour && !q.per_day) throw new Error('Set an hourly or daily limit, or remove the quota.')
  return { client_credentials: q }
}
