<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type EmailPreview, type EmailTemplateName } from '../../api/client'
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
const savedExists = ref(false)
const savedEnabled = ref(false)
const savedSubject = ref('')
const savedBody = ref('')
const draftSubject = ref('')
const draftBody = ref('')
const preview = ref<EmailPreview>()
const loading = ref(true)
const loadFailed = ref(false)
const rendering = ref(false)
const sending = ref(false)
const error = ref('')
const status = ref('')
let requestNumber = 0
const sandboxDocument = computed(() => preview.value ? `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-src 'none'"></head><body>${preview.value.html}</body></html>` : '')

async function loadTemplate() {
  const current = tenant.value
  if (!current) { loading.value = false; return }
  const sequence = ++requestNumber
  const template = selected.value
  loading.value = true
  error.value = ''
  status.value = ''
  loadFailed.value = false
  preview.value = undefined
  try {
    const saved = await api.getEmailTemplate(current, template)
    if (sequence !== requestNumber) return
    savedExists.value = true
    savedEnabled.value = saved.enabled
    savedSubject.value = saved.subject
    savedBody.value = saved.body
    draftSubject.value = saved.subject
    draftBody.value = saved.body
  } catch (e) {
    if (sequence !== requestNumber) return
    if (e instanceof ApiError && e.status === 404) {
      savedExists.value = false
      savedEnabled.value = false
      savedSubject.value = ''
      savedBody.value = ''
      draftSubject.value = ''
      draftBody.value = ''
    } else { error.value = errorMessage(e); loadFailed.value = true }
  } finally { if (sequence === requestNumber) loading.value = false }
}

watch([tenant, selected], () => { void loadTemplate() }, { immediate: true })

async function renderPreview() {
  const current = tenant.value
  if (!current || loading.value || loadFailed.value || !savedExists.value || rendering.value) return
  const sequence = requestNumber
  const name = selected.value
  rendering.value = true
  error.value = ''
  status.value = ''
  const overrides: Record<string, unknown> = {}
  if (draftBody.value !== savedBody.value) overrides.body = draftBody.value
  if (draftSubject.value !== savedSubject.value) overrides.subject = draftSubject.value
  try {
    const rendered = await api.previewTenantEmail(current, { template: name, ...(Object.keys(overrides).length ? { overrides } : {}) })
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name) preview.value = rendered
  } catch (e) {
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name) error.value = errorMessage(e)
  } finally { rendering.value = false }
}

async function refreshSavedState(current: NonNullable<typeof tenant.value>, name: EmailTemplateName, sequence: number) {
  try {
    const saved = await api.getEmailTemplate(current, name)
    if (sequence !== requestNumber || tenant.value?.name !== current.name || selected.value !== name) return
    savedExists.value = true
    savedEnabled.value = saved.enabled
    savedSubject.value = saved.subject
    savedBody.value = saved.body
  } catch (e) {
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name && e instanceof ApiError && e.status === 404) savedExists.value = false
  }
}

async function sendTest() {
  const current = tenant.value
  if (!current || loading.value || loadFailed.value || !savedExists.value || !savedEnabled.value || sending.value) return
  const sequence = requestNumber
  const name = selected.value
  sending.value = true
  status.value = ''
  error.value = ''
  try {
    const outcome = await api.testTenantEmail(current, { template: name })
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name) status.value = outcome ? t('emails.customTestResult', { status: outcome.status, reason: outcome.reason ?? '—', execution: outcome.execution_id ?? '—' }) : t('emails.testAccepted')
  } catch {
    await refreshSavedState(current, name, sequence)
    if (sequence === requestNumber && tenant.value?.name === current.name && selected.value === name) status.value = t('emails.testUncertain')
  } finally { sending.value = false }
}
</script>

<template>
  <section class="grid max-w-3xl gap-4" aria-labelledby="email-preview-heading">
    <h2 id="email-preview-heading" class="m-0">{{ t('emails.previewTab') }}</h2>
    <p class="m-0 text-muted">{{ t('emails.testSavedHint') }}</p>
    <Field id="email-preview-template" :label="t('emails.template')">
      <select id="email-preview-template" v-model="selected" :disabled="rendering || sending">
        <option v-for="name in names" :key="name" :value="name">{{ t(`emails.templateNames.${name}`) }}</option>
      </select>
    </Field>
    <p v-if="loading" role="status" class="text-muted">{{ t('emails.loading') }}</p>
    <Banner v-else-if="loadFailed" kind="error">{{ error }} <Button variant="ghost" @click="loadTemplate">{{ t('emails.retry') }}</Button></Banner>
    <template v-else>
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Banner v-if="!savedExists || !savedEnabled" kind="warn">{{ !savedExists ? t('emails.missingTemplate') : t('emails.disabledTemplate') }}</Banner>
      <template v-else>
        <div class="grid gap-4 md:grid-cols-2">
          <Field id="email-preview-subject" :label="t('emails.previewSubject')"><input id="email-preview-subject" v-model="draftSubject" :disabled="rendering || sending" /></Field>
          <Field id="email-preview-body" :label="t('emails.previewBody')"><textarea id="email-preview-body" v-model="draftBody" rows="8" :disabled="rendering || sending" /></Field>
        </div>
        <p class="m-0 text-sm text-muted">{{ t('emails.syntheticHint') }}</p>
        <div class="flex flex-wrap gap-2">
          <Button :disabled="rendering || sending" @click="renderPreview">{{ rendering ? t('emails.saving') : t('emails.renderPreview') }}</Button>
          <Button variant="ghost" :disabled="rendering || sending || !savedExists || !savedEnabled" @click="sendTest">{{ sending ? t('emails.saving') : t('emails.testSaved') }}</Button>
        </div>
        <Banner v-if="status" kind="info">{{ status }}</Banner>
        <section v-if="preview" aria-labelledby="email-preview-result" class="grid gap-2">
          <h3 id="email-preview-result" class="m-0">{{ t('emails.renderedPreview') }}</h3>
          <p class="m-0"><strong>{{ preview.subject }}</strong></p>
          <p class="m-0 text-sm text-muted">{{ preview.from }} · {{ preview.resultUrl }}</p>
          <iframe title="Rendered email preview" sandbox="" :srcdoc="sandboxDocument" class="min-h-96 w-full rounded border border-rule bg-white" />
        </section>
      </template>
    </template>
  </section>
</template>
