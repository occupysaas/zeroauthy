import { defineStore } from 'pinia'
import { computed, shallowRef } from 'vue'

export interface SessionUser {
  authenticated: boolean
  email: string
  sub: string
}

// The signed-in operator, as the auth service reports it. It reads the
// auth service's own reactive user, so there is nothing to keep in sync.
// Tokens are never held here.
export const useSessionStore = defineStore('session', () => {
  const user = shallowRef<SessionUser>({ authenticated: false, email: '', sub: '' })

  function attach(u: SessionUser): void {
    user.value = u
  }

  const authenticated = computed(() => user.value.authenticated)
  const email = computed(() => user.value.email)
  const sub = computed(() => user.value.sub)

  return { attach, authenticated, email, sub }
})
