<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Job, JobError, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; jobId: string }>()
const { api } = useServices()

// What the server answers: the failed records, nothing (an export), or the
// job itself (an import that failed as a whole). The records come with
// their secrets already masked by the server; they are shown exactly as
// they arrive and are never rewritten, expanded or kept anywhere.
const loading = ref(true)
const error = ref('')
const records = ref<JobError[] | null>(null)
const failed = ref<Job | null>(null)

onMounted(async () => {
  try {
    const r = await api.getJobErrors(props.tenant, props.jobId)
    if (Array.isArray(r)) records.value = r
    else if (r) failed.value = r
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
})

const show = (v: unknown) => JSON.stringify(v, null, 2)
</script>

<template>
  <div class="stack" data-testid="job-errors">
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <template v-else-if="failed">
      <p class="m-0">{{ t('jobs.errors.jobFailed') }}</p>
      <p v-if="failed.status_details" class="m-0 font-bold">{{ failed.status_details }}</p>
    </template>
    <p v-else-if="records === null" class="muted m-0">{{ t('jobs.errors.none') }}</p>
    <p v-else-if="records.length === 0" class="muted m-0">{{ t('jobs.errors.noRecords') }}</p>
    <template v-else>
      <p class="muted m-0">{{ t('jobs.errors.masked') }}</p>
      <ol class="m-0 grid list-none gap-3 p-0">
        <li v-for="(r, i) in records" :key="i" class="rounded border border-hair p-3">
          <p class="m-0 font-bold">{{ t('jobs.errors.record', { n: i + 1 }) }}</p>
          <pre class="mono m-0 overflow-x-auto" :aria-label="t('jobs.errors.recordLabel', { n: i + 1 })">{{ show(r.user) }}</pre>
          <ul class="m-0 mt-2">
            <li v-for="(e, j) in r.errors ?? []" :key="j">
              <span class="mono">{{ e.code }}</span>
              <span>: {{ e.message }}</span>
              <span v-if="e.path" class="muted"> ({{ t('jobs.errors.path') }} <span class="mono">{{ e.path }}</span>)</span>
            </li>
          </ul>
        </li>
      </ol>
    </template>
  </div>
</template>
