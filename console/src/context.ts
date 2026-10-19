import { computed, inject, type ComputedRef, type InjectionKey } from 'vue'
import { useRoute } from 'vue-router'
import type { Api, SystemTenant } from './api/client'
import type { Auth } from './auth/auth'
import { useTenantsStore } from './stores/tenants'

export interface Services {
  auth: Auth
  api: Api
}

export const servicesKey: InjectionKey<Services> = Symbol('services')

export function useServices(): Services {
  const s = inject(servicesKey)
  if (!s) throw new Error('console services are not provided')
  return s
}

// useTenant is the tenant named by the current route, if the operator
// manages it.
export function useTenant(): ComputedRef<SystemTenant | undefined> {
  const route = useRoute()
  const tenants = useTenantsStore()
  return computed(() => {
    const name = route.params.tenant
    return typeof name === 'string' ? tenants.find(name) : undefined
  })
}

// errorMessage turns anything thrown into text for the page.
export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}
