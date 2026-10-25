<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type EmailTemplate, type EmailTemplateName } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { emailTemplateNames } from './templates'

const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const names = emailTemplateNames
const selected = ref<EmailTemplateName>('verify_email')
const exists = ref(false)
const enabled = ref(false)
const subject = ref('')
const from = ref('')
const body = ref('')
const resultUrl = ref('')
const lifetime = ref<number | null>(null)
const includeEmail = ref(false)
const loading = ref(true)
const loadFailed = ref(false)
const saving = ref(false)
const error = ref('')
const status = ref('')
let requestNumber = 0
const savedState = computed(() => !exists.value ? t('emails.missingTemplate') : enabled.value ? t('emails.savedTemplate') : t('emails.disabledTemplate'))

function setDraft(template?: EmailTemplate) {
  exists.value = !!template
  enabled.value = template?.enabled ?? false
  subject.value = template?.subject ?? ''
  from.value = template?.from ?? ''
  body.value = template?.body ?? ''
  resultUrl.value = template?.resultUrl ?? ''
  lifetime.value = template?.urlLifetimeInSeconds ?? null
  includeEmail.value = template?.includeEmailInRedirect ?? false
}

async function load() {
  const current = tenant.value
  if (!current) { loading.value = false; return }
  const sequence = ++requestNumber
  const name = selected.value
  loading.value = true
  error.value = ''
  status.value = ''
  loadFailed.value = false
  try {
    const template = await api.getEmailTemplate(current, name)
    if (sequence !== requestNumber) return
    setDraft(template)
  } catch (e) {
    if (sequence !== requestNumber) return
    if (e instanceof ApiError && e.status === 404) setDraft(undefined)
    else { error.value = errorMessage(e); loadFailed.value = true }
  } finally { if (sequence === requestNumber) loading.value = false }
}

watch([tenant, selected], () => { void load() }, { immediate: true })

function uncertain(e: unknown): boolean { return !(e instanceof ApiError) || e.status >= 500 || e.status === 408 }

async function refreshRemote(current: NonNullable<typeof tenant.value>, name: EmailTemplateName, sequence: number) {
  try {
    await api.getEmailTemplate(current, name)
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name) exists.value = true
  } catch (e) {
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name && e instanceof ApiError && e.status === 404) exists.value = false
  }
}

async function save() {
  const current = tenant.value
  if (!current || loading.value || loadFailed.value || saving.value) return
  const sequence = requestNumber
  const name = selected.value
  saving.value = true
  error.value = ''
  status.value = ''
  const draft: EmailTemplate = {
    template: selected.value, body: body.value, subject: subject.value, enabled: enabled.value, syntax: 'liquid',
    ...(from.value ? { from: from.value } : {}), ...(resultUrl.value ? { resultUrl: resultUrl.value } : {}),
    ...(lifetime.value !== null ? { urlLifetimeInSeconds: lifetime.value } : {}), ...(includeEmail.value ? { includeEmailInRedirect: true } : {}),
  }
  try {
    const saved = exists.value ? await api.putEmailTemplate(current, name, draft) : await api.createEmailTemplate(current, draft)
    if (sequence !== requestNumber || tenant.value?.name !== current.name || selected.value !== name) return
    setDraft(saved)
    status.value = t('emails.saved')
  } catch (e) {
    if (sequence !== requestNumber || tenant.value?.name !== current.name || selected.value !== name) return
    if (uncertain(e)) { await refreshRemote(current, name, sequence); error.value = t('emails.saveUncertain') }
    else error.value = errorMessage(e)
  } finally { saving.value = false }
}
</script>

<template>
  <section class="grid max-w-3xl gap-4" aria-labelledby="email-templates-heading">
    <h2 id="email-templates-heading" class="m-0">{{ t('emails.templatesTab') }}</h2>
    <p class="m-0 text-muted">{{ t('emails.templatesHint') }}</p>
    <Field id="email-template-select" :label="t('emails.template')">
      <select id="email-template-select" v-model="selected" :disabled="saving">
        <option v-for="name in names" :key="name" :value="name">{{ t(`emails.templateNames.${name}`) }}</option>
      </select>
    </Field>
    <p v-if="loading" role="status" class="text-muted">{{ t('emails.loading') }}</p>
    <Banner v-else-if="loadFailed" kind="error">{{ error }} <Button variant="ghost" @click="load">{{ t('emails.retry') }}</Button></Banner>
    <template v-else>
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Banner kind="info">{{ savedState }}</Banner>
      <label class="flex items-center gap-2"><input v-model="enabled" type="checkbox" :disabled="saving" />{{ t('emails.enabled') }}</label>
      <Field id="email-template-from" :label="t('emails.from')"><input id="email-template-from" v-model="from" type="email" :disabled="saving" /></Field>
      <Field id="email-template-subject" :label="t('emails.subject')"><input id="email-template-subject" v-model="subject" :disabled="saving" /></Field>
      <Field id="email-template-result-url" :label="t('emails.resultUrl')"><input id="email-template-result-url" v-model="resultUrl" type="url" :disabled="saving" /></Field>
      <Field id="email-template-lifetime" :label="t('emails.lifetime')"><input id="email-template-lifetime" v-model.number="lifetime" type="number" min="0" max="604800" :disabled="saving" /></Field>
      <label class="flex items-center gap-2"><input v-model="includeEmail" type="checkbox" :disabled="saving" />{{ t('emails.includeEmail') }}</label>
      <Field id="email-template-body" :label="t('emails.body')"><textarea id="email-template-body" v-model="body" rows="12" :disabled="saving" /></Field>
      <Banner v-if="status" kind="info">{{ status }}</Banner>
      <Button :disabled="saving" @click="save">{{ saving ? t('emails.saving') : t('emails.saveTemplate') }}</Button>
    </template>
  </section>
</template>
