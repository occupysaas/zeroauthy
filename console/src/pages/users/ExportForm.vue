<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, Job, SystemTenant, UsersExportJobCreate } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { DEFAULT_EXPORT_FIELDS, MAX_EXPORT_FIELDS } from './jobs'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant }>()
const emit = defineEmits<{ created: [Job] }>()
const { api } = useServices()

// The longest name or export_as the server takes.
const MAX_NAME = 100

const connections = ref<Connection[]>([])
const loadError = ref('')
const connection = ref('')
const format = ref<'csv' | 'json'>('csv')
const limit = ref('')
const chosen = ref<string[]>([...DEFAULT_EXPORT_FIELDS])
interface Extra {
  key: number
  name: string
  exportAs: string
}
const extras = ref<Extra[]>([])
let nextKey = 0
const errors = ref<{ limit?: string; fields?: string }>({})
const failure = ref('')
const queued = ref('')
const busy = ref(false)

onMounted(async () => {
  try {
    connections.value = await api.allDatabaseConnections(props.tenant)
  } catch (e) {
    loadError.value = errorMessage(e)
  }
})

const count = computed(() => chosen.value.length + extras.value.length)
const full = computed(() => count.value >= MAX_EXPORT_FIELDS)

function toggleDefault(name: string, on: boolean) {
  // Keep the default order whatever order they are ticked in.
  chosen.value = DEFAULT_EXPORT_FIELDS.filter((f) => (f === name ? on : chosen.value.includes(f)))
}
function addField() {
  if (!full.value) extras.value.push({ key: nextKey++, name: '', exportAs: '' })
}
function removeField(key: number) {
  extras.value = extras.value.filter((e) => e.key !== key)
}

// Whole metadata objects have no CSV cell; the server writes them empty.
const wholeMetadata = (name: string) => name === 'user_metadata' || name === 'app_metadata'

// fieldsError explains what is wrong with the field choice, or ''.
function fieldsError(): string {
  if (count.value === 0) return t('jobs.export.noFields')
  if (count.value > MAX_EXPORT_FIELDS) return t('jobs.export.tooMany', { max: MAX_EXPORT_FIELDS })
  for (const e of extras.value) {
    const name = e.name.trim()
    if (!name) return t('jobs.export.nameRequired')
    if (name.length > MAX_NAME || e.exportAs.trim().length > MAX_NAME) return t('jobs.export.nameTooLong', { max: MAX_NAME })
    if (format.value === 'csv' && wholeMetadata(name)) return t('jobs.export.metadataSubfield', { name })
  }
  return ''
}

async function submit() {
  failure.value = ''
  queued.value = ''
  const next: { limit?: string; fields?: string } = {}
  let lim: number | undefined
  if (limit.value.trim() !== '') {
    lim = Number(limit.value)
    if (!Number.isInteger(lim) || lim < 1) next.limit = t('jobs.export.limitInvalid')
  }
  next.fields = fieldsError() || undefined
  errors.value = next
  if (next.limit || next.fields || busy.value) return

  const body: UsersExportJobCreate = { format: format.value }
  if (connection.value) body.connection_id = connection.value
  if (lim !== undefined) body.limit = lim
  // Left out, the server writes the default columns.
  if (chosen.value.length !== DEFAULT_EXPORT_FIELDS.length || extras.value.length > 0) {
    body.fields = [
      ...chosen.value.map((name) => ({ name })),
      ...extras.value.map((e) => (e.exportAs.trim() ? { name: e.name.trim(), export_as: e.exportAs.trim() } : { name: e.name.trim() })),
    ]
  }
  busy.value = true
  try {
    const job = await api.createExportJob(props.tenant, body)
    queued.value = t('jobs.export.queued', { id: job.id })
    emit('created', job)
  } catch (e) {
    failure.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card stack" aria-labelledby="export-title">
    <h2 id="export-title" class="m-0">{{ t('jobs.export.title') }}</h2>
    <p class="muted m-0">{{ t('jobs.export.intro') }}</p>
    <Banner v-if="loadError" kind="error">{{ loadError }}</Banner>
    <form class="stack" novalidate @submit.prevent="submit">
      <Field id="export-connection" :label="t('jobs.export.connection')">
        <select id="export-connection" v-model="connection">
          <option value="">{{ t('jobs.export.allConnections') }}</option>
          <option v-for="c in connections" :key="c.id" :value="c.id">{{ c.name }}</option>
        </select>
      </Field>
      <Field id="export-format" :label="t('jobs.export.format')">
        <select id="export-format" v-model="format">
          <option value="csv">CSV</option>
          <option value="json">{{ t('jobs.export.json') }}</option>
        </select>
      </Field>
      <Field id="export-limit" :label="t('jobs.export.limit')" :hint="t('jobs.export.limitHint')" :error="errors.limit">
        <input id="export-limit" v-model="limit" type="text" inputmode="numeric" autocomplete="off" :aria-invalid="!!errors.limit" :aria-describedby="'export-limit-hint' + (errors.limit ? ' export-limit-error' : '')" />
      </Field>

      <fieldset class="stack m-0 rounded border border-hair p-3" aria-describedby="export-fields-hint">
        <legend class="font-bold">{{ t('jobs.export.fields') }}</legend>
        <p id="export-fields-hint" class="muted m-0">{{ t('jobs.export.fieldsHint', { max: MAX_EXPORT_FIELDS }) }}</p>
        <div class="grid gap-1 sm:grid-cols-2">
          <label v-for="f in DEFAULT_EXPORT_FIELDS" :key="f" class="flex items-center gap-2">
            <input type="checkbox" :checked="chosen.includes(f)" :disabled="full && !chosen.includes(f)" @change="toggleDefault(f, ($event.target as HTMLInputElement).checked)" />
            <span class="mono">{{ f }}</span>
          </label>
        </div>
        <div v-for="(e, i) in extras" :key="e.key" class="row items-start" role="group" :aria-label="t('jobs.export.extraGroup', { n: i + 1 })">
          <Field :id="'export-extra-name-' + e.key" :label="t('jobs.export.fieldName')">
            <input :id="'export-extra-name-' + e.key" v-model="e.name" type="text" class="mono" autocomplete="off" spellcheck="false" :placeholder="t('jobs.export.fieldNamePlaceholder')" />
          </Field>
          <Field :id="'export-extra-as-' + e.key" :label="t('jobs.export.exportAs')">
            <input :id="'export-extra-as-' + e.key" v-model="e.exportAs" type="text" autocomplete="off" spellcheck="false" />
          </Field>
          <Button class="self-end" @click="removeField(e.key)">{{ t('jobs.export.removeField') }}</Button>
        </div>
        <p v-if="errors.fields" id="export-fields-error" class="m-0 text-sm text-danger" role="alert">{{ errors.fields }}</p>
        <div class="row">
          <Button :disabled="full" @click="addField">{{ t('jobs.export.addField') }}</Button>
          <span class="muted" aria-live="polite">{{ t('jobs.export.fieldCount', { n: count, max: MAX_EXPORT_FIELDS }) }}</span>
        </div>
      </fieldset>

      <Banner v-if="failure" kind="error">{{ failure }}</Banner>
      <p v-if="queued" role="status" class="m-0">{{ queued }}</p>
      <div class="row"><Button variant="primary" type="submit" :disabled="busy">{{ t('jobs.export.submit') }}</Button></div>
    </form>
  </section>
</template>
