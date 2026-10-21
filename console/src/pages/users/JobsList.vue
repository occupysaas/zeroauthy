<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Job, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Modal from '../../ui/Modal.vue'
import Tag from '../../ui/Tag.vue'
import JobErrors from './JobErrors.vue'
import { POLL_MS, followLocation, isPending, weakHashAdviceURL } from './jobs'

const { t, locale } = useI18n()
const props = defineProps<{ tenant: SystemTenant; refresh: number }>()
const { api } = useServices()

const PER_PAGE = 20
const jobs = ref<Job[]>([])
const total = ref(0)
const page = ref(0)
const loading = ref(true)
const error = ref('')
const notice = ref('')
const downloading = ref('')
const errorsFor = ref<Job | null>(null)
const errorsOpen = computed({
  get: () => errorsFor.value !== null,
  set: (v: boolean) => {
    if (!v) errorsFor.value = null
  },
})

let seq = 0
let timer: ReturnType<typeof setTimeout> | undefined
const hidden = () => document.visibilityState === 'hidden'

function stop() {
  if (timer !== undefined) clearTimeout(timer)
  timer = undefined
}
// Pending jobs are re-read every few seconds while the page is in view; with
// none pending, or the page hidden, nothing is polled.
function schedule() {
  stop()
  if (hidden() || !jobs.value.some(isPending)) return
  timer = setTimeout(() => {
    timer = undefined
    void load(true)
  }, POLL_MS)
}

async function load(quiet = false) {
  const mine = ++seq
  if (!quiet) loading.value = true
  error.value = ''
  try {
    const res = await api.listJobs(props.tenant, { page: page.value, per_page: PER_PAGE })
    if (mine !== seq) return
    jobs.value = res.jobs ?? []
    total.value = res.total ?? 0
  } catch (e) {
    if (mine !== seq) return
    error.value = errorMessage(e)
    if (!quiet) jobs.value = []
  } finally {
    if (mine === seq) {
      loading.value = false
      schedule()
    }
  }
}

function onVisibility() {
  if (hidden()) stop()
  else void load(true)
}

onMounted(() => {
  document.addEventListener('visibilitychange', onVisibility)
  void load()
})
onBeforeUnmount(() => {
  document.removeEventListener('visibilitychange', onVisibility)
  stop()
  seq++
})
watch(() => props.refresh, () => void load(true))
watch(() => props.tenant.name, () => {
  page.value = 0
  void load()
})

function go(p: number) {
  page.value = p
  void load()
}

const from = computed(() => (total.value === 0 ? 0 : page.value * PER_PAGE + 1))
const to = computed(() => Math.min(total.value, (page.value + 1) * PER_PAGE))

const typeLabel = (j: Job) => t(`jobs.list.types.${j.type}`)
const statusLabel = (j: Job) => t(`jobs.list.statuses.${j.status}`)

function summaryOf(j: Job): string {
  if (j.type !== 'users_import') return ''
  const s = j.summary
  if (!s) return ''
  return t('jobs.list.summary', { inserted: s.inserted ?? 0, updated: s.updated ?? 0, failed: s.failed ?? 0, total: s.total ?? 0 })
}
const hasErrors = (j: Job) => j.type === 'users_import' && (j.status === 'failed' || (j.status === 'completed' && (j.summary?.failed ?? 0) > 0))
const canDownload = (j: Job) => j.type === 'users_export' && j.status === 'completed'

// A download link works for a minute, so each click reads the job again and
// follows the link that read returns; no link is kept.
async function download(j: Job) {
  notice.value = ''
  error.value = ''
  downloading.value = j.id
  try {
    const fresh = await api.getJob(props.tenant, j.id)
    if (fresh.status === 'completed' && fresh.location) followLocation(fresh.location)
    else notice.value = t('jobs.list.noFile')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    downloading.value = ''
  }
}
</script>

<template>
  <section class="stack" aria-labelledby="jobs-title">
    <div class="row">
      <h2 id="jobs-title" class="m-0">{{ t('jobs.list.title') }}</h2>
      <span class="flex-1" />
      <Button @click="load()">{{ t('jobs.list.refresh') }}</Button>
    </div>
    <p class="muted m-0">{{ t('jobs.list.keptFor') }}</p>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load()">{{ t('retry') }}</Button>
    </Banner>
    <p v-if="notice" role="status" class="m-0">{{ notice }}</p>
    <p v-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="jobs.length === 0 && !error" class="card empty [&_p]:my-1">
      <p>{{ t('jobs.list.empty') }}</p>
      <p class="muted">{{ t('jobs.list.emptyHint') }}</p>
    </div>
    <template v-else-if="jobs.length > 0">
      <table class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('jobs.list.type') }}</th>
            <th scope="col">{{ t('jobs.list.status') }}</th>
            <th scope="col">{{ t('jobs.list.created') }}</th>
            <th scope="col">{{ t('jobs.list.connection') }}</th>
            <th scope="col">{{ t('jobs.list.summaryColumn') }}</th>
            <th scope="col"><span class="visually-hidden">{{ t('jobs.list.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="j in jobs" :key="j.id" :data-job="j.id">
            <td>{{ typeLabel(j) }}<br /><span class="muted mono">{{ j.id }}</span></td>
            <td>
              <Tag>{{ statusLabel(j) }}</Tag>
              <p v-if="j.status === 'failed' && j.status_details" class="m-0 mt-1 text-sm">{{ j.status_details }}</p>
            </td>
            <td><time :datetime="j.created_at" :title="j.created_at">{{ new Date(j.created_at).toLocaleString(locale) }}</time></td>
            <td>{{ j.connection || (j.type === 'users_export' ? t('jobs.list.allConnections') : '') }}</td>
            <td>
              <span v-if="summaryOf(j)">{{ summaryOf(j) }}</span>
              <p v-if="(j.weak_hashes ?? 0) > 0" class="m-0 mt-1 text-sm">
                {{ t('jobs.list.weakHashes', { n: j.weak_hashes ?? 0 }) }}
                <a :href="weakHashAdviceURL" target="_blank" rel="noopener noreferrer">{{ t('jobs.list.weakHashAdvice') }}</a>
              </p>
            </td>
            <td>
              <div class="row">
                <Button v-if="hasErrors(j)" @click="errorsFor = j">{{ t('jobs.list.errors') }}</Button>
                <Button v-if="canDownload(j)" :disabled="downloading === j.id" @click="download(j)">{{ t('jobs.list.download') }}</Button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <nav class="row" :aria-label="t('navPages')">
        <span class="muted" aria-live="polite">{{ t('jobs.list.range', { from, to, total }) }}</span>
        <span class="flex-1" />
        <Button :disabled="page === 0" @click="go(page - 1)">{{ t('users.previous') }}</Button>
        <Button :disabled="to >= total" @click="go(page + 1)">{{ t('users.next') }}</Button>
      </nav>
    </template>

    <Modal v-model:open="errorsOpen" :title="t('jobs.errors.title')" :description="errorsFor ? errorsFor.id : undefined">
      <JobErrors v-if="errorsFor" :key="errorsFor.id" :tenant="tenant" :job-id="errorsFor.id" />
    </Modal>
  </section>
</template>
