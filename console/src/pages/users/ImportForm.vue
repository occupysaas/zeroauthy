<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, Job, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Toggle from '../../ui/Toggle.vue'
import { optionsOf } from '../connections/options'
import { MAX_IMPORT_FILE_BYTES, importableConnections } from './jobs'

const { t, n } = useI18n()
const props = defineProps<{ tenant: SystemTenant }>()
const emit = defineEmits<{ created: [Job] }>()
const { api } = useServices()

const connections = ref<Connection[]>([])
const loadError = ref('')
const connection = ref('')
const upsert = ref(false)
const completionEmail = ref(true)
const file = ref<File | null>(null)
const input = ref<HTMLInputElement | null>(null)
const errors = ref<{ file?: string; connection?: string }>({})
const failure = ref('')
const busy = ref(false)
const queued = ref('')

const options = computed(() => importableConnections(connections.value))

onMounted(async () => {
  try {
    connections.value = await api.allDatabaseConnections(props.tenant)
  } catch (e) {
    loadError.value = errorMessage(e)
  }
})

function pick(e: Event) {
  file.value = (e.target as HTMLInputElement).files?.[0] ?? null
  errors.value = { ...errors.value, file: undefined }
}

// validate checks before anything is uploaded; the server checks again.
function validate(): boolean {
  const next: { file?: string; connection?: string } = {}
  if (!file.value) next.file = t('jobs.import.fileRequired')
  else if (file.value.size === 0) next.file = t('jobs.import.fileEmpty')
  else if (file.value.size > MAX_IMPORT_FILE_BYTES) next.file = t('jobs.import.fileTooLarge', { limit: n(MAX_IMPORT_FILE_BYTES), size: n(file.value.size) })
  if (!connection.value) next.connection = t('jobs.import.connectionRequired')
  errors.value = next
  return !next.file && !next.connection
}

async function submit() {
  failure.value = ''
  queued.value = ''
  if (!validate() || busy.value) return
  const form = new FormData()
  form.append('connection_id', connection.value)
  form.append('upsert', String(upsert.value))
  form.append('send_completion_email', String(completionEmail.value))
  // The file goes last: the server reads the other parts before it.
  form.append('users', file.value!, file.value!.name)
  busy.value = true
  try {
    const job = await api.createImportJob(props.tenant, form)
    queued.value = t('jobs.import.queued', { id: job.id })
    file.value = null
    if (input.value) input.value.value = ''
    emit('created', job)
  } catch (e) {
    failure.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

const label = (c: Connection) => c.name + (optionsOf(c).enabledDatabaseCustomization === true ? ' ' + t('jobs.import.customDb') : '')
</script>

<template>
  <section class="card stack" aria-labelledby="import-title">
    <h2 id="import-title" class="m-0">{{ t('jobs.import.title') }}</h2>
    <p class="muted m-0">{{ t('jobs.import.intro', { limit: n(MAX_IMPORT_FILE_BYTES) }) }}</p>
    <Banner v-if="loadError" kind="error">{{ loadError }}</Banner>
    <form class="stack" novalidate @submit.prevent="submit">
      <Field id="import-file" :label="t('jobs.import.file')" :hint="t('jobs.import.fileHint', { limit: n(MAX_IMPORT_FILE_BYTES) })" :error="errors.file">
        <input id="import-file" ref="input" type="file" accept=".json,application/json" :aria-invalid="!!errors.file" :aria-describedby="'import-file-hint' + (errors.file ? ' import-file-error' : '')" @change="pick" />
      </Field>
      <Field id="import-connection" :label="t('jobs.import.connection')" :hint="t('jobs.import.connectionHint')" :error="errors.connection">
        <select id="import-connection" v-model="connection" :aria-invalid="!!errors.connection" :aria-describedby="'import-connection-hint' + (errors.connection ? ' import-connection-error' : '')">
          <option value="">{{ t('jobs.import.choose') }}</option>
          <option v-for="c in options" :key="c.id" :value="c.id">{{ label(c) }}</option>
        </select>
      </Field>
      <Toggle v-model="upsert" :label="t('jobs.import.upsert')" />
      <Toggle v-model="completionEmail" :label="t('jobs.import.completionEmail')" />
      <Banner v-if="failure" kind="error">{{ failure }}</Banner>
      <p v-if="queued" role="status" class="m-0">{{ queued }}</p>
      <div class="row"><Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('jobs.import.uploading') : t('jobs.import.submit') }}</Button></div>
    </form>
  </section>
</template>
