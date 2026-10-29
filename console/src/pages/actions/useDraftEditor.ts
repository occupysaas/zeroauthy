import { computed, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ActionDependency, ActionSecretInput, SystemTenant } from '../../api/client'
import { errorMessage } from '../../context'
import { exactVersion, packageName, pendingBuild, type useActionContext } from './context'

type Draft = { name: string; code: string; dependencies: ActionDependency[]; secrets: ActionSecretInput[] }
type Resource = Draft & { status: string }
type Context = ReturnType<typeof useActionContext>
type Options<R extends Resource> = {
  context: Context
  limits: { name: number; code: number; codeUnit: 'bytes' | 'characters'; invalid: string }
  read: (tenant: SystemTenant, id: string) => Promise<R>
  update: (tenant: SystemTenant, id: string, draft: Draft) => Promise<R>
  publish: (tenant: SystemTenant, id: string, resource: R) => Promise<R>
  published: string
  extraDraft?: () => unknown
  validateExtra?: () => string | undefined
  applyExtra?: (resource: R) => void
  resetExtra?: () => void
}

// Shared write-only draft lifecycle. Resource-specific wire payloads and limits
// remain explicit adapters in the Action and Module editors.
export function useDraftEditor<R extends Resource>(options: Options<R>) {
  const { t } = useI18n(), { key, capture, current } = options.context
  const resource = shallowRef<R>(), name = ref(''), code = ref(''), dependencies = ref<ActionDependency[]>([]), secrets = ref<ActionSecretInput[]>([])
  const loading = ref(false), busy = ref(false), error = ref(''), notice = ref(''), reloadRequired = ref(false), baseline = ref('')
  let poll: ReturnType<typeof setTimeout> | undefined, readSeq = 0
  const draft = (): Draft => ({ name: name.value, code: code.value, dependencies: dependencies.value.map(d => ({ ...d })), secrets: secrets.value.map(s => ({ ...s })) })
  const snapshot = () => JSON.stringify([draft(), options.extraDraft?.()])
  const dirty = computed(() => snapshot() !== baseline.value)
  function stopPolling() { clearTimeout(poll); poll = undefined }
  function apply(value: R) {
    resource.value = value; name.value = value.name; code.value = value.code
    dependencies.value = value.dependencies.map(d => ({ ...d }))
    secrets.value = value.secrets.map(s => ({ name: s.name }))
    options.applyExtra?.(value); baseline.value = snapshot()
  }
  function schedule(c: ReturnType<typeof capture>) {
    stopPolling()
    if (current(c) && pendingBuild(resource.value?.status)) poll = setTimeout(() => { void read(true) }, 1500)
  }
  async function read(preserve = false) {
    const c = capture(), seq = ++readSeq
    if (!c) return
    if (!preserve) loading.value = true
    error.value = ''
    try {
      const value = await options.read(c.tenant, c.id)
      if (!current(c) || seq !== readSeq) return
      if (preserve) resource.value = value
      else apply(value)
      reloadRequired.value = false; schedule(c)
    } catch (e) { if (current(c) && seq === readSeq) error.value = errorMessage(e) }
    finally { if (current(c) && seq === readSeq) loading.value = false }
  }
  function validate() {
    const extra = options.validateExtra?.()
    if (extra) { error.value = t(extra); return false }
    const size = options.limits.codeUnit === 'bytes' ? new TextEncoder().encode(code.value).length : [...code.value].length
    if (!name.value || [...name.value].length > options.limits.name || size > options.limits.code) { error.value = t(options.limits.invalid); return false }
    const packages = new Set<string>()
    for (const d of dependencies.value) {
      if (d.name.length > 214 || !packageName.test(d.name) || packages.has(d.name) || (d.version && d.version !== 'latest' && !exactVersion.test(d.version))) { error.value = t('actions.invalidDependency'); return false }
      packages.add(d.name)
    }
    const names = new Set<string>()
    for (const s of secrets.value) {
      if (!/^[A-Za-z0-9_]{1,128}$/.test(s.name) || names.has(s.name) || (s.value !== undefined && new TextEncoder().encode(s.value).length > 4096)) { error.value = t('actions.invalidSecret'); return false }
      names.add(s.name)
    }
    return true
  }
  async function save() {
    const c = capture()
    if (!c || !resource.value || busy.value || reloadRequired.value || !validate()) return
    stopPolling(); ++readSeq; busy.value = true; notice.value = ''; error.value = ''
    try {
      const value = await options.update(c.tenant, c.id, draft())
      if (!current(c)) return
      apply(value); notice.value = t('actions.saved'); schedule(c)
    } catch (e) { if (current(c)) { error.value = errorMessage(e); reloadRequired.value = true } }
    finally { if (current(c)) busy.value = false }
  }
  async function reload() {
    if (busy.value) return
    busy.value = true
    const c = capture()
    await read(true)
    if (current(c)) busy.value = false
  }
  async function publish() {
    const c = capture(), value = resource.value
    if (!c || !value || busy.value || dirty.value || reloadRequired.value || value.status !== 'built') return
    busy.value = true; error.value = ''; notice.value = ''; stopPolling(); ++readSeq
    try {
      const published = await options.publish(c.tenant, c.id, value)
      if (current(c)) { resource.value = published; notice.value = t(options.published) }
    } catch (e) { if (current(c)) { error.value = errorMessage(e); reloadRequired.value = true } }
    finally { if (current(c)) busy.value = false }
  }
  watch(key, () => {
    stopPolling(); ++readSeq; resource.value = undefined; name.value = ''; code.value = ''; dependencies.value = []; secrets.value = []; baseline.value = ''; busy.value = false; loading.value = false; reloadRequired.value = false; error.value = ''; notice.value = ''
    options.resetExtra?.(); void read()
  }, { immediate: true })
  onBeforeUnmount(stopPolling)
  return { resource, name, code, dependencies, secrets, loading, busy, error, notice, reloadRequired, dirty, read, save, reload, publish }
}
