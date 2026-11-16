import { expect, it } from 'vitest'
import en from '../../locales/en'
import { protectionPanels } from './panels'

it('labels the custom token exchange throttle stage like the live stages', () => {
  const ip = protectionPanels.find((p) => p.key === 'ip')!
  const stage = ip.fields.filter((f) => JSON.stringify(f).includes('pre-custom-token-exchange'))
  expect(stage).toHaveLength(2)
  for (const f of stage) expect(JSON.stringify(f)).not.toContain('future')
  expect(JSON.stringify(stage)).toContain('policy.capacityHint')
  expect(JSON.stringify(stage)).toContain('policy.rateHint')
  expect(en.policy.capacityHint).toBeTruthy()
})
