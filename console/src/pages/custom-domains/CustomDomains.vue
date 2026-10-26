<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import type { CustomDomain } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import { statusLabel } from './labels'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const router = useRouter()

const domains = ref<CustomDomain[]>([])
const configuredDefault = ref<CustomDomain | null>(null)
const loading = ref(true)
const readable = ref(false) // writes stay locked until a read succeeds
const error = ref('')
const pending = ref(false)
// The add form's draft survives failed reads and errors.
const name = ref('')
const kind = ref<'auth0_managed_certs' | 'self_managed_certs'>('auth0_managed_certs')
let generation = 0
let readSequence = 0
let poll: ReturnType<typeof setTimeout> | undefined
let polls = 0
function stopPoll() { clearTimeout(poll); poll = undefined }
onBeforeUnmount(() => { generation++; readSequence++; stopPoll() })

async function load(background = false) {
  const tn = tenant.value
  if (!tn) return
  const current = generation
  const sequence = ++readSequence
  if (!background) loading.value = true
  error.value = ''
  try {
    const [list, def] = await Promise.all([api.listCustomDomains(tn), api.getDefaultCustomDomain(tn)])
    if (current !== generation || sequence !== readSequence) return
    domains.value = list
    configuredDefault.value = def.custom_domain_id ? def : null
    readable.value = true
  } catch (e) {
    if (current !== generation || sequence !== readSequence) return
    readable.value = false
    error.value = errorMessage(e)
  } finally {
    if (current === generation && sequence === readSequence) loading.value = false
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
watch(tenant, () => {
  generation++; readSequence++; stopPoll(); polls = 0
  pending.value = false; domains.value = []; configuredDefault.value = null; readable.value = false
  void load(); schedulePoll(generation)
}, { immediate: true })

const canonical = computed(() => tenant.value?.host ?? '')
const readyDomains = computed(() => domains.value.filter(d => d.status === 'ready'))
const defaultValue = computed(() => configuredDefault.value?.domain ?? canonical.value)
const unusableDefault = computed(() => configuredDefault.value && configuredDefault.value.status !== 'ready' ? configuredDefault.value.domain : '')

async function add() {
  const tn = tenant.value
  if (!tn || !readable.value || pending.value || !name.value.trim()) return
  const current = generation
  pending.value = true
  error.value = ''
  try {
    const created = await api.createCustomDomain(tn, { domain: name.value.trim(), type: kind.value })
    if (current !== generation) return
    name.value = ''
    await router.push({ name: 'custom-domain', params: { tenant: tn.name, id: created.custom_domain_id } })
  } catch (e) {
    if (current !== generation) return
    error.value = errorMessage(e)
  } finally {
    if (current === generation) pending.value = false
  }
}

async function setDefault(host: string) {
  const tn = tenant.value
  if (!tn || !readable.value || pending.value) return
  const current = generation
  pending.value = true
  error.value = ''
  try {
    await api.setDefaultCustomDomain(tn, host)
  } catch (e) {
    if (current !== generation) return
    error.value = errorMessage(e)
  } finally {
    if (current === generation) pending.value = false
  }
  if (current === generation) await load()
}
</script>

<template>
  <div v-if="tenant">
    <h1>{{ t('customDomain.title') }}</h1>
    <p>{{ t('customDomain.intro') }}</p>
    <Banner v-if="!readable && !loading" kind="error">
      {{ t('customDomain.loadFailed') }} {{ error }}
      <Button variant="ghost" @click="load()">{{ t('retry') }}</Button>
    </Banner>
    <Banner v-else-if="error" kind="error">{{ error }}</Banner>
    <Banner v-if="unusableDefault" kind="warn">{{ t('customDomain.defaultUnavailable', { domain: unusableDefault }) }}</Banner>

    <form class="row mb-4" :aria-label="t('customDomain.add')" @submit.prevent="add">
      <label for="domain-name">{{ t('customDomain.domain') }}</label>
      <input id="domain-name" v-model="name" type="text" autocomplete="off" spellcheck="false" required>
      <label for="domain-type">{{ t('customDomain.type') }}</label>
      <select id="domain-type" v-model="kind">
        <option value="auth0_managed_certs">{{ t('customDomain.managed') }}</option>
        <option value="self_managed_certs">{{ t('customDomain.selfManaged') }}</option>
      </select>
      <button type="submit" class="button" :disabled="!readable || pending">{{ pending ? t('customDomain.adding') : t('customDomain.add') }}</button>
    </form>

    <section v-if="readable" aria-labelledby="default-title" class="mb-4">
      <h2 id="default-title">{{ t('customDomain.default') }}</h2>
      <p>{{ t('customDomain.defaultHelp') }}</p>
      <label for="default-domain" class="sr-only">{{ t('customDomain.default') }}</label>
      <select id="default-domain" :value="defaultValue" :disabled="pending" @change="setDefault(($event.target as HTMLSelectElement).value)">
        <option :value="canonical">{{ t('customDomain.canonical', { host: canonical }) }}</option>
        <option v-for="d in readyDomains" :key="d.custom_domain_id" :value="d.domain">{{ d.domain }}</option>
      </select>
      <Button v-if="configuredDefault" :disabled="pending" @click="setDefault(canonical)">{{ t('customDomain.useCanonical') }}</Button>
    </section>

    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <table v-else-if="domains.length" class="table">
      <thead><tr><th>{{ t('customDomain.domain') }}</th><th>{{ t('customDomain.status') }}</th><th>{{ t('customDomain.type') }}</th></tr></thead>
      <tbody>
        <tr v-for="d in domains" :key="d.custom_domain_id">
          <td>
            <RouterLink :to="{ name: 'custom-domain', params: { tenant: tenant.name, id: d.custom_domain_id } }">{{ d.domain }}</RouterLink>
            <span v-if="d.is_default"> · {{ t('customDomain.isDefault') }}</span>
          </td>
          <td>{{ statusLabel(t, d.status) }}</td>
          <td>{{ d.type === 'self_managed_certs' ? t('customDomain.selfManaged') : t('customDomain.managed') }}</td>
        </tr>
      </tbody>
    </table>
    <p v-else-if="readable">{{ t('customDomain.empty') }}</p>
  </div>
</template>
