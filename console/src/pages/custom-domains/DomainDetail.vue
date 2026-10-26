<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, type CustomDomain } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import DNSInstructions from './DNSInstructions.vue'
import ProxySecret from './ProxySecret.vue'
import { certificateLabel, statusLabel, verificationLabel } from './labels'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const route = useRoute()
const router = useRouter()

const domain = ref<CustomDomain | null>(null)
const error = ref('')
const notice = ref('')
const pending = ref(false)
const readable = ref(false)
const dirty = ref(false)
// secret holds the one-time key from this page's own verify reply only.
const secret = ref('')
const header = ref<string>('')
const metadata = ref('')
const rp = ref('')
let generation = 0
let readSequence = 0
let poll: ReturnType<typeof setTimeout> | undefined
let polls = 0
function stopPoll() { clearTimeout(poll); poll = undefined }
onBeforeUnmount(() => { generation++; readSequence++; stopPoll(); secret.value = '' })

const id = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))

function fill(d: CustomDomain, preserveDraft = false) {
  domain.value = d
  if (preserveDraft && dirty.value) return
  dirty.value = false
  header.value = d.custom_client_ip_header ?? ''
  metadata.value = Object.entries(d.domain_metadata ?? {}).map(([k, v]) => `${k}=${v}`).join('\n')
  rp.value = d.relying_party_identifier ?? ''
}

async function load(preserveDraft = false) {
  const tn = tenant.value
  if (!tn || !id.value) return
  const current = generation
  const sequence = ++readSequence
  error.value = ''
  try {
    const d = await api.getCustomDomain(tn, id.value)
    if (current === generation && sequence === readSequence) { fill(d, preserveDraft); readable.value = true }
  } catch (e) {
    if (current === generation && sequence === readSequence) { readable.value = false; error.value = errorMessage(e) }
  }
}
function schedulePoll(current: number) {
  if (current !== generation || polls >= 120) return
  poll = setTimeout(async () => {
    polls++
    if (!pending.value) await load(true)
    schedulePoll(current)
  }, 5000)
}
watch([tenant, id], () => {
  generation++; readSequence++; stopPoll(); polls = 0
  pending.value = false; readable.value = false; dirty.value = false
  secret.value = ''; notice.value = ''; domain.value = null
  void load(); schedulePoll(generation)
}, { immediate: true })

const certificate = computed(() => domain.value?.certificate)

async function verify() {
  const tn = tenant.value
  if (!tn || !domain.value || !readable.value || pending.value) return
  pending.value = true
  error.value = ''
  notice.value = ''
  const current = generation
  try {
    // Never retried: only this reply can carry the one-time key.
    const res = await api.verifyCustomDomain(tn, domain.value.custom_domain_id!)
    if (current !== generation) return
    const { cname_api_key: key, ...rest } = res
    if (key) secret.value = key
    fill(rest as CustomDomain)
  } catch (e) {
    if (current !== generation) return
    if (e instanceof ApiError && e.status === 429) {
      error.value = t('customDomain.retryAfter', { seconds: e.retryAfter ?? 30 })
    } else if (e instanceof ApiError && e.status >= 400 && e.status < 500) {
      error.value = errorMessage(e)
    } else {
      // The reply may be lost after commit: refresh status, never retry.
      notice.value = t('customDomain.verifyUncertain')
      await load()
    }
  } finally {
    if (current === generation) pending.value = false
  }
}

async function test() {
  const tn = tenant.value
  if (!tn || !domain.value || !readable.value || pending.value) return
  const current = generation
  pending.value = true
  error.value = ''
  notice.value = ''
  try {
    const res = await api.testCustomDomain(tn, domain.value.custom_domain_id!)
    if (current !== generation) return
    notice.value = res.success ? t('customDomain.testOk') : t('customDomain.testFailed', { message: res.message ?? '' })
  } catch (e) {
    if (current !== generation) return
    error.value = e instanceof ApiError && e.status === 429 ? t('customDomain.retryAfter', { seconds: e.retryAfter ?? 30 }) : errorMessage(e)
  } finally {
    if (current === generation) pending.value = false
  }
}

function parseMetadata(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const i = line.indexOf('=')
    if (i <= 0) continue
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return out
}

async function save() {
  const tn = tenant.value
  if (!tn || !domain.value || !readable.value || pending.value) return
  const current = generation
  pending.value = true
  error.value = ''
  notice.value = ''
  try {
    const d = await api.updateCustomDomain(tn, domain.value.custom_domain_id!, {
      custom_client_ip_header: header.value === '' ? null : header.value,
      domain_metadata: parseMetadata(metadata.value),
      relying_party_identifier: rp.value,
    })
    if (current !== generation) return
    fill(d)
    notice.value = t('customDomain.saved')
  } catch (e) {
    if (current !== generation) return
    error.value = errorMessage(e)
  } finally {
    if (current === generation) pending.value = false
  }
}

async function remove() {
  const tn = tenant.value
  if (!tn || !domain.value || !readable.value || pending.value) return
  if (!globalThis.confirm(t('customDomain.confirmDelete', { domain: domain.value.domain }))) return
  const current = generation
  pending.value = true
  try {
    await api.deleteCustomDomain(tn, domain.value.custom_domain_id!)
    if (current !== generation) return
    await router.push({ name: 'custom-domains', params: { tenant: tn.name } })
  } catch (e) {
    if (current !== generation) return
    error.value = errorMessage(e)
  } finally {
    if (current === generation) pending.value = false
  }
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'custom-domains', params: { tenant: tenant.name } }">{{ t('customDomain.back') }}</RouterLink>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <Banner v-if="notice" kind="info">{{ notice }}</Banner>
    <template v-if="domain">
      <h1>{{ domain.domain }}</h1>
      <ProxySecret v-if="secret" :secret="secret" @done="secret = ''" />
      <dl>
        <dt>{{ t('customDomain.status') }}</dt><dd>{{ statusLabel(t, domain.status) }}</dd>
        <dt>{{ t('customDomain.verification') }}</dt>
        <dd>{{ verificationLabel(t, domain.verification?.status) }}<span v-if="domain.verification?.error_msg"> — {{ domain.verification.error_msg }}</span></dd>
        <template v-if="certificate">
          <dt>{{ t('customDomain.certificate') }}</dt>
          <dd>
            {{ certificateLabel(t, certificate.status) }}<span v-if="certificate.error_msg"> — {{ certificate.error_msg }}</span>
            <span v-if="certificate.renews_before"> · {{ t('customDomain.expires', { date: certificate.renews_before.slice(0, 10) }) }}</span>
          </dd>
        </template>
      </dl>
      <div class="row mb-4">
        <Button :disabled="!readable || pending" @click="verify">{{ pending ? t('customDomain.verifying') : t('customDomain.verify') }}</Button>
        <Button :disabled="!readable || pending || domain.status !== 'ready'" @click="test">{{ t('customDomain.test') }}</Button>
      </div>
      <DNSInstructions :domain="domain" />
      <form id="domain-settings" aria-labelledby="settings-title" @submit.prevent="save" @input="dirty = true" @change="dirty = true">
        <h2 id="settings-title">{{ t('customDomain.settings') }}</h2>
        <label for="client-ip">{{ t('customDomain.clientIP') }}</label>
        <select id="client-ip" v-model="header" aria-describedby="client-ip-help">
          <option value="">{{ t('customDomain.clientIPNone') }}</option>
          <option value="x-forwarded-for">x-forwarded-for</option>
          <option value="true-client-ip">true-client-ip</option>
          <option value="cf-connecting-ip">cf-connecting-ip</option>
          <option value="x-azure-clientip">x-azure-clientip</option>
        </select>
        <p id="client-ip-help">{{ t('customDomain.clientIPHelp') }}</p>
        <label for="metadata">{{ t('customDomain.metadata') }}</label>
        <textarea id="metadata" v-model="metadata" rows="4" aria-describedby="metadata-help" />
        <p id="metadata-help">{{ t('customDomain.metadataHelp') }}</p>
        <label for="rp">{{ t('customDomain.rp') }}</label>
        <input id="rp" v-model="rp" type="text" aria-describedby="rp-help">
        <p id="rp-help">{{ t('customDomain.rpHelp') }}</p>
        <button type="submit" class="button" :disabled="!readable || pending">{{ t('customDomain.save') }}</button>
      </form>
      <Button variant="danger" class="mt-4" :disabled="!readable || pending" @click="remove">{{ t('customDomain.delete') }}</Button>
    </template>
  </div>
</template>
