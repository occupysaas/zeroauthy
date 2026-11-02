import { computed, onBeforeUnmount, watch } from 'vue'
import { useRoute } from 'vue-router'
import { ApiError, type SystemTenant } from '../../api/client'

// An epoch also rejects A→B→A responses and replies after navigation/unmount.
export function useMfaScope(tenant: () => SystemTenant | undefined, id: () => string = () => '') {
  const route = useRoute()
  const key = computed(() => JSON.stringify([tenant(), id(), route.fullPath]))
  let epoch = 0, alive = true
  watch(key, () => { ++epoch }, { flush: 'sync' })
  onBeforeUnmount(() => { alive = false; ++epoch })
  function capture() { const tn = tenant(); return tn ? { tenant: tn, id: id(), epoch } : undefined }
  function current(c: ReturnType<typeof capture>) { return !!c && alive && c.epoch === epoch }
  return { key, capture, current }
}
export const mfaUnavailable = (e: unknown) => e instanceof ApiError && (e.errorCode === 'mfa_unavailable' || e.status === 501)
