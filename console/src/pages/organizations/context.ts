import { onBeforeUnmount, ref, toValue, watch, type WatchSource } from 'vue'
import { errorMessage } from '../../context'

// Each panel owns its request sequence and write epoch, including on unmount.
// A failed write retains the draft and requires an explicit server reload.
export function usePanel<T>(key: WatchSource, read: () => Promise<T>, apply: (value: T) => void, reset: () => void = () => {}) {
  const loading = ref(true), busy = ref(false), error = ref(''), status = ref(''), reloadRequired = ref(false)
  let epoch = 0, seq = 0
  const capture = () => epoch
  const current = (mine: number) => mine === epoch
  async function load() {
    const mine = epoch, request = ++seq
    loading.value = true; error.value = ''
    try {
      const result = await read()
      if (mine !== epoch || request !== seq) return
      apply(result); reloadRequired.value = false
    } catch (e) { if (mine === epoch && request === seq) error.value = errorMessage(e) }
    finally { if (mine === epoch && request === seq) loading.value = false }
  }
  async function change(write: () => Promise<unknown>, done: () => void | Promise<void> = load) {
    if (busy.value || reloadRequired.value) return
    const mine = epoch
    ++seq; busy.value = true; error.value = ''; status.value = ''
    try { await write(); if (mine === epoch) await done() }
    catch (e) { if (mine === epoch) { error.value = errorMessage(e); reloadRequired.value = true } }
    finally { if (mine === epoch) busy.value = false }
  }
  watch(() => JSON.stringify(toValue(key)), () => { ++epoch; ++seq; busy.value = false; error.value = ''; status.value = ''; reloadRequired.value = false; reset(); void load() }, { immediate: true })
  onBeforeUnmount(() => { ++epoch; ++seq })
  return { loading, busy, error, status, reloadRequired, load, change, capture, current }
}
export const validName = (value: string) => /^[a-z0-9][a-z0-9_-]{0,49}$/.test(value)
export function metadataValue(text: string): Record<string, string> | undefined {
  try {
    const value: unknown = JSON.parse(text)
    if (!value || typeof value !== 'object' || Array.isArray(value)) return
    const entries = Object.entries(value)
    if (entries.length > 25 || entries.some(([k,v]) => !/^[a-zA-Z0-9]\w{0,49}$/.test(k) || typeof v !== 'string' || [...v].length < 1 || [...v].length > 255)) return
    return value as Record<string, string>
  } catch { return }
}
