import { computed, onBeforeUnmount, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useServices, useTenant } from '../../context'

// Each asynchronous operation captures both the resource and tenant. An epoch
// also rejects A→B→A replies; comparing only the final route would accept them.
export function useActionContext() {
  const route = useRoute(), tenant = useTenant(), { api } = useServices()
  const id = computed(() => String(route.params.id ?? ''))
  const trigger = computed(() => String(route.params.trigger ?? ''))
  const key = computed(() => JSON.stringify([route.fullPath, tenant.value]))
  let epoch = 0, alive = true
  watch(key, () => { ++epoch }, { flush: 'sync' })
  onBeforeUnmount(() => { alive = false; ++epoch })
  function capture() {
    const tn = tenant.value
    if (!tn) return
    return { tenant: tn, id: id.value, trigger: trigger.value, key: key.value, epoch }
  }
  function current(c: ReturnType<typeof capture>) { return !!c && alive && c.key === key.value && c.epoch === epoch }
  return { api, tenant, id, trigger, key, capture, current }
}

export const pendingBuild = (status?: string) => ['pending', 'building', 'packaged', 'retrying'].includes(status ?? '')
export const exactVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/
export const packageName = /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/

const buildKeys: Record<string, string> = {
  pending: 'actions.build.pending', building: 'actions.build.building',
  packaged: 'actions.build.packaged', built: 'actions.build.built',
  retrying: 'actions.build.retrying', failed: 'actions.build.failed',
}
export const buildStatusKey = (status?: string) => buildKeys[status ?? ''] ?? 'actions.status'
