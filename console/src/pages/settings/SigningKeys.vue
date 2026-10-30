<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type ManagedSigningKey, type SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import ConfirmPrompt from '../../ui/ConfirmPrompt.vue'
import { useConfirm } from '../../ui/confirm'

const props = defineProps<{ tenant: SystemTenant }>()
const { t } = useI18n()
const { api } = useServices()
const prompt = useConfirm()
const keys = ref<ManagedSigningKey[]>([])
const error = ref('')
const loading = ref(false)
const pending = ref(false)
const uncertain = ref(false)
const generation = ref(0)
let tenantGeneration = 0
let disposed = false
onBeforeUnmount(() => { disposed = true; generation.value++ })

async function refresh() {
  const current = ++generation.value
  const host = props.tenant.host
  loading.value = true
  error.value = ''
  try {
    const result = await api.listSigningKeys(props.tenant)
    if (disposed || current !== generation.value || host !== props.tenant.host) return
    keys.value = result
    uncertain.value = false
  } catch (e) {
    if (!disposed && current === generation.value) error.value = e instanceof Error ? e.message : String(e)
  } finally {
    if (!disposed && current === generation.value) loading.value = false
  }
}
watch(() => props.tenant.host, () => { tenantGeneration++; pending.value = false; uncertain.value = false; keys.value = []; void refresh() }, { immediate: true })

async function mutate(kind: 'rotate' | 'revoke', key?: ManagedSigningKey) {
  if (props.tenant.reserved || loading.value || pending.value || uncertain.value) return
  if (kind === 'revoke' && (!key || !keys.value.some(k => k.kid === key.kid && k.previous && !k.revoked))) return
  const message = kind === 'rotate' ? t('signingKeys.confirmRotate') : t('signingKeys.confirmRevoke', { kid: key?.kid })
  if (!(await prompt.ask(message, kind === 'rotate' ? t('signingKeys.rotate') : t('signingKeys.revoke')))) return
  const tenant = props.tenant
  const currentTenant = tenantGeneration
  pending.value = true
  error.value = ''
  try {
    if (kind === 'rotate') await api.rotateSigningKeys(tenant)
    else if (key) await api.revokeSigningKey(tenant, key.kid)
    if (disposed || currentTenant !== tenantGeneration) return
    await refresh()
  } catch (e) {
    if (!disposed && currentTenant === tenantGeneration) {
      error.value = e instanceof Error ? e.message : String(e)
      if (e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 408) return
      uncertain.value = true
      // The mutation may have committed even when its response was lost.
      await refresh()
    }
  } finally {
    if (!disposed && currentTenant === tenantGeneration) pending.value = false
  }
}

async function copy(key: ManagedSigningKey) {
  try { await navigator.clipboard.writeText(key.cert ?? '') }
  catch (e) { error.value = e instanceof Error ? e.message : String(e) }
}

function download(key: ManagedSigningKey) {
  if (!key.cert) return
  const url = URL.createObjectURL(new Blob([key.cert], { type: 'application/x-pem-file' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${key.kid}.pem`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <section aria-labelledby="signing-keys-title">
    <h2 id="signing-keys-title">{{ t('signingKeys.managedTitle') }}</h2>
    <Banner v-if="tenant.reserved" kind="warn">{{ t('signingKeys.reserved') }}</Banner>
    <Banner v-if="error" kind="error" role="alert">{{ error }}</Banner>
    <Banner v-if="uncertain" kind="warn">{{ t('signingKeys.uncertain') }}</Banner>
    <p>{{ t('signingKeys.publicOnly') }}</p>
    <button type="button" class="button" :disabled="loading" @click="refresh">{{ t('signingKeys.refresh') }}</button>
    <button type="button" class="button" :disabled="tenant.reserved || loading || pending || uncertain" @click="mutate('rotate')">{{ t('signingKeys.rotate') }}</button>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <table v-if="keys.length" class="table mt-4">
      <thead><tr><th>{{ t('signingKeys.kid') }}</th><th>{{ t('signingKeys.algorithm') }}</th><th>{{ t('signingKeys.status') }}</th><th>{{ t('signingKeys.currentSince') }}</th><th>{{ t('signingKeys.currentUntil') }}</th><th>{{ t('signingKeys.revokedAt') }}</th><th>{{ t('signingKeys.actions') }}</th></tr></thead>
      <tbody><tr v-for="key in keys" :key="key.kid">
        <td>{{ key.kid }}<dl v-if="key.fingerprint || key.thumbprint" class="text-sm"><dt>{{ t('signingKeys.fingerprint') }}</dt><dd>{{ key.fingerprint ?? '—' }}</dd><dt>{{ t('signingKeys.thumbprint') }}</dt><dd>{{ key.thumbprint ?? '—' }}</dd></dl></td><td>{{ key.alg }}</td>
        <td>{{ key.current ? t('signingKeys.current') : key.next ? t('signingKeys.next') : key.previous ? t('signingKeys.previous') : t('signingKeys.revoked') }}</td>
        <td>{{ key.current_since ?? '—' }}</td><td>{{ key.current_until ?? '—' }}</td><td>{{ key.revoked_at ?? '—' }}</td>
        <td><button v-if="key.cert" type="button" class="button" @click="copy(key)">{{ t('signingKeys.copy') }}</button>
          <button v-if="key.cert" type="button" class="button" @click="download(key)">{{ t('signingKeys.download') }}</button>
          <button v-if="key.previous && !key.revoked" type="button" class="button" :disabled="tenant.reserved || loading || pending || uncertain" @click="mutate('revoke', key)">{{ t('signingKeys.revoke') }}</button></td>
      </tr></tbody>
    </table>
    <p v-else-if="!loading">{{ t('signingKeys.empty') }}</p>
    <ConfirmPrompt :prompt="prompt" />
  </section>
</template>
