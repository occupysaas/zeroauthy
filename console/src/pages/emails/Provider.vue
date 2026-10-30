<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type EmailProvider, type EmailProviderWrite } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmPrompt from '../../ui/ConfirmPrompt.vue'
import { useConfirm } from '../../ui/confirm'
import Field from '../../ui/Field.vue'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const prompt = useConfirm()
const names = ['smtp', 'sendgrid', 'mailgun', 'mandrill', 'sparkpost', 'ses', 'azure_cs', 'ms365', 'resend', 'custom'] as const
type ProviderName = typeof names[number]
const credentialFields: Record<ProviderName, string[]> = {
  smtp: ['smtp_host', 'smtp_port', 'smtp_user', 'smtp_pass'], sendgrid: ['api_key'], mailgun: ['api_key', 'domain', 'region'],
  mandrill: ['api_key'], sparkpost: ['api_key', 'region'], ses: [], azure_cs: ['connectionString'],
  ms365: ['tenantId', 'clientId', 'clientSecret'], resend: ['api_key'], custom: [],
}
const secretFields = new Set(['smtp_pass', 'api_key', 'clientSecret', 'connectionString'])
const name = ref<ProviderName>('sendgrid')
const enabled = ref(false)
const defaultFrom = ref('')
const settingsText = ref('')
const credentials = reactive<Record<string, string>>({})
const exists = ref(false)
const loading = ref(true)
const loadFailed = ref(false)
const saving = ref(false)
const deleting = ref(false)
const error = ref('')
const status = ref('')
let requestNumber = 0
const inputFields = computed(() => credentialFields[name.value])

function clearCredentials() {
  for (const key of Object.keys(credentials)) delete credentials[key]
}

function applyProvider(provider: EmailProvider | undefined) {
  clearCredentials()
  exists.value = !!provider
  name.value = (provider?.name as ProviderName | undefined) ?? 'sendgrid'
  enabled.value = provider?.enabled ?? false
  defaultFrom.value = provider?.default_from_address ?? ''
  settingsText.value = provider?.settings ? JSON.stringify(provider.settings, null, 2) : ''
}

async function load() {
  const current = tenant.value
  if (!current) { loading.value = false; return }
  const sequence = ++requestNumber
  loading.value = true
  error.value = ''
  status.value = ''
  loadFailed.value = false
  try {
    const provider = await api.getEmailProvider(current)
    if (sequence !== requestNumber) return
    applyProvider(provider)
  } catch (e) {
    if (sequence !== requestNumber) return
    if (e instanceof ApiError && e.status === 404) applyProvider(undefined)
    else { error.value = errorMessage(e); loadFailed.value = true }
  } finally {
    if (sequence === requestNumber) loading.value = false
  }
}

watch(tenant, () => { clearCredentials(); void load() }, { immediate: true })

function uncertain(e: unknown): boolean {
  return !(e instanceof ApiError) || e.status >= 500 || e.status === 408
}

async function refreshRemote(current: NonNullable<typeof tenant.value>, sequence: number) {
  try {
    const saved = await api.getEmailProvider(current)
    if (sequence !== requestNumber || tenant.value?.name !== current.name) return
    exists.value = true
    // Keep the form draft after an uncertain write response.
    void saved
  } catch (e) {
    if (sequence === requestNumber && tenant.value?.name === current.name && e instanceof ApiError && e.status === 404) exists.value = false
  }
}

async function save() {
  const current = tenant.value
  if (!current || loading.value || loadFailed.value || saving.value) return
  const sequence = requestNumber
  saving.value = true
  error.value = ''
  status.value = ''
  try {
    const body: EmailProviderWrite = { name: name.value, enabled: enabled.value, default_from_address: defaultFrom.value || null }
    const entered = Object.fromEntries(Object.entries(credentials).filter(([, value]) => value.trim() !== ''))
    if (Object.keys(entered).length) body.credentials = entered
    if (settingsText.value.trim()) {
      const settings: unknown = JSON.parse(settingsText.value)
      if (!settings || typeof settings !== 'object' || Array.isArray(settings)) throw new Error('Settings must be a JSON object.')
      body.settings = settings as Record<string, unknown>
    }
    const saved = exists.value ? await api.updateEmailProvider(current, body) : await api.createEmailProvider(current, body)
    if (sequence !== requestNumber || tenant.value?.name !== current.name) return
    applyProvider(saved)
    status.value = t('emails.saved')
  } catch (e) {
    if (uncertain(e)) {
      if (sequence !== requestNumber || tenant.value?.name !== current.name) return
      await refreshRemote(current, sequence)
      error.value = t('emails.saveUncertain')
    } else if (sequence === requestNumber && tenant.value?.name === current.name) error.value = errorMessage(e)
  } finally { saving.value = false }
}

async function remove() {
  const current = tenant.value
  if (!current || !exists.value || deleting.value) return
  if (!(await prompt.ask(t('emails.confirmDeleteProvider'), t('emails.deleteProvider')))) return
  if (tenant.value?.name !== current.name || !exists.value || deleting.value) return
  const sequence = requestNumber
  deleting.value = true
  error.value = ''
  status.value = ''
  try {
    await api.deleteEmailProvider(current)
    if (sequence !== requestNumber || tenant.value?.name !== current.name) return
    applyProvider(undefined)
    status.value = t('emails.providerMissing')
  } catch (e) {
    if (sequence !== requestNumber || tenant.value?.name !== current.name) return
    if (uncertain(e)) { await refreshRemote(current, sequence); error.value = t('emails.deleteUncertain') }
    else error.value = errorMessage(e)
  } finally { deleting.value = false }
}
</script>

<template>
  <section class="grid max-w-2xl gap-4" aria-labelledby="email-provider-heading">
    <h2 id="email-provider-heading" class="m-0">{{ t('emails.providerTab') }}</h2>
    <p v-if="loading" role="status" class="text-muted">{{ t('emails.loading') }}</p>
    <Banner v-else-if="loadFailed" kind="error">{{ error }} <Button variant="ghost" @click="load">{{ t('emails.retry') }}</Button></Banner>
    <template v-else>
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Banner kind="info">{{ exists ? t('emails.providerStored') : t('emails.providerMissing') }}</Banner>
      <Field id="email-provider-name" :label="t('emails.providerName')">
        <select id="email-provider-name" v-model="name" :disabled="saving || deleting">
          <option v-for="item in names" :key="item" :value="item">{{ t(`emails.providerNames.${item}`) }}</option>
        </select>
      </Field>
      <label class="flex items-center gap-2"><input v-model="enabled" type="checkbox" :disabled="saving || deleting" />{{ t('emails.enabled') }}</label>
      <p v-if="name === 'custom'" class="muted">{{ t('emails.customBindingHint') }}</p>
      <Field id="email-default-from" :label="t('emails.defaultFrom')"><input id="email-default-from" v-model="defaultFrom" type="email" :disabled="saving || deleting" /></Field>
      <p class="m-0 text-sm text-muted">{{ t('emails.credentialsHint') }}</p>
      <Field v-for="field in inputFields" :key="field" :id="'credential-' + field" :label="t(`emails.credentialNames.${field}`)">
        <input :id="'credential-' + field" v-model="credentials[field]" :type="secretFields.has(field) ? 'password' : 'text'" autocomplete="new-password" :disabled="saving || deleting" />
      </Field>
      <Field id="email-provider-settings" :label="t('emails.settings')" :hint="t('emails.settingsHint')"><textarea id="email-provider-settings" v-model="settingsText" rows="4" :disabled="saving || deleting" /></Field>
      <Banner v-if="status" kind="info">{{ status }}</Banner>
      <div class="flex flex-wrap gap-2">
        <Button :disabled="saving || deleting" @click="save">{{ saving ? t('emails.saving') : t('emails.saveProvider') }}</Button>
        <Button v-if="exists" variant="ghost" :disabled="saving || deleting" @click="remove">{{ t('emails.deleteProvider') }}</Button>
      </div>
    </template>
    <ConfirmPrompt :prompt="prompt" />
  </section>
</template>
