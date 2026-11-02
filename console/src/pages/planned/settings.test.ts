import { expect, it } from 'vitest'
import { plannedPages } from './index'
import { routes } from '../../router'
import Mfa from '../security/Mfa.vue'

it('replaces the planned MFA preview with the live Security page', () => {
  expect(plannedPages.mfa).toBeUndefined()
  expect(routes.find(route => route.name === 'mfa')?.component).toBe(Mfa)
})
