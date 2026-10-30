<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type CustomSigningJWKS, type SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import ConfirmPrompt from '../../ui/ConfirmPrompt.vue'
import { useConfirm } from '../../ui/confirm'

const props = defineProps<{ tenant: SystemTenant }>()
const { t } = useI18n()
const { api } = useServices()
const prompt = useConfirm()
const text = ref('{\n  "keys": []\n}')
const error = ref('')
const busy = ref(false)
const loading = ref(false)
const generation = ref(0)
let disposed = false
onBeforeUnmount(() => { disposed = true; generation.value++ })
watch(() => props.tenant.host, async () => {
  const current = ++generation.value
  error.value = ''
  busy.value = false
  loading.value = true
  text.value = '{\n  "keys": []\n}'
  try {
    const data = await api.getCustomSigningKeys(props.tenant)
    if (!disposed && current === generation.value) text.value = JSON.stringify(data, null, 2)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      if (!disposed && current === generation.value) { text.value = '{\n  "keys": []\n}'; error.value = '' }
      return
    }
    if (!disposed && current === generation.value) {
      text.value = '{\n  "keys": []\n}'
      error.value = e instanceof Error ? e.message : String(e)
    }
  } finally { if (!disposed && current === generation.value) loading.value = false }
}, { immediate: true })

function validate(): CustomSigningJWKS {
  if (new TextEncoder().encode(text.value).length > 64 * 1024) throw new Error(t('signingKeys.tooLarge'))
  let parsed: unknown
  try { parsed = JSON.parse(text.value) } catch { throw new Error(t('signingKeys.invalidJSON')) }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as { keys?: unknown }).keys)) throw new Error(t('signingKeys.invalidJWKS'))
  const keys = (parsed as { keys: Record<string, unknown>[] }).keys
  if (keys.length < 1 || keys.length > 10) throw new Error(t('signingKeys.invalidJWKS'))
  if (keys.some(key => !key || typeof key !== 'object' || Array.isArray(key))) throw new Error(t('signingKeys.invalidJWKS'))
  if (keys.some(key => Object.keys(key).some(name => ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'].includes(name)))) throw new Error(t('signingKeys.privateMaterial'))
  return parsed as CustomSigningJWKS
}
async function replace() {
  if (props.tenant.reserved || loading.value || busy.value) return
  let payload: CustomSigningJWKS
  try { payload = validate() } catch (e) { error.value = e instanceof Error ? e.message : String(e); return }
  if (!(await prompt.ask(t('signingKeys.confirmReplace'), t('signingKeys.replace')))) return
  const current = generation.value
  const tenant = props.tenant
  busy.value = true; error.value = ''
  try {
    const saved = await api.putCustomSigningKeys(tenant, payload)
    if (!disposed && current === generation.value) text.value = JSON.stringify(saved, null, 2)
  } catch (e) { if (!disposed && current === generation.value) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (!disposed && current === generation.value) busy.value = false }
}
async function remove() {
  if (props.tenant.reserved || loading.value || busy.value) return
  if (!(await prompt.ask(t('signingKeys.confirmDelete'), t('signingKeys.delete')))) return
  const current = generation.value
  const tenant = props.tenant
  busy.value = true; error.value = ''
  try {
    await api.deleteCustomSigningKeys(tenant)
    if (!disposed && current === generation.value) text.value = '{\n  "keys": []\n}'
  } catch (e) { if (!disposed && current === generation.value) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (!disposed && current === generation.value) busy.value = false }
}
</script>

<template>
  <section aria-labelledby="custom-signing-title">
    <h2 id="custom-signing-title">{{ t('signingKeys.customTitle') }}</h2>
    <Banner kind="info">{{ t('signingKeys.storedOnly') }}</Banner>
    <Banner v-if="tenant.reserved" kind="warn">{{ t('signingKeys.reserved') }}</Banner>
    <Banner v-if="error" kind="error" role="alert">{{ error }}</Banner>
    <label for="custom-signing-jwks">{{ t('signingKeys.jwks') }}</label>
    <textarea id="custom-signing-jwks" v-model="text" class="input mt-2 min-h-64 w-full font-mono" spellcheck="false" :disabled="busy || loading" maxlength="65536" />
    <div class="mt-3 flex gap-2"><button type="button" class="button" :disabled="tenant.reserved || loading || busy" @click="replace">{{ t('signingKeys.replace') }}</button>
      <button type="button" class="button" :disabled="tenant.reserved || loading || busy" @click="remove">{{ t('signingKeys.delete') }}</button></div>
    <ConfirmPrompt :prompt="prompt" />
  </section>
</template>
