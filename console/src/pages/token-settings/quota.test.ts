import { describe, expect, it } from 'vitest'
import { quotaDraft, quotaValue } from './quota'
describe('quota drafts', () => {
  it('retains saved hourly/daily limits when enforcement changes and sends null for clearing', () => {
    const d = quotaDraft({ client_credentials: { enforce: true, per_hour: 10, per_day: 50 } })
    d.enforce = false
    expect(quotaValue(d)).toEqual({ client_credentials: { enforce: false, per_hour: 10, per_day: 50 } })
    d.enabled = false
    expect(quotaValue(d)).toBeNull()
  })
  it.each(['0', '-1', '1.5', '2147483648', 'Infinity'])('rejects an invalid enabled limit %s', value => {
    expect(() => quotaValue({ enabled: true, enforce: true, hour: value, day: '' })).toThrow()
  })
  it('does not allow an empty override or silently encode an unlimited quota', () => {
    expect(() => quotaValue({ enabled: true, enforce: true, hour: '', day: '' })).toThrow()
  })
})
