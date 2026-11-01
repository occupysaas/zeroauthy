<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { SystemExecution } from '../../api/client'
defineProps<{ execution: SystemExecution; tenantName: string }>()
const { t } = useI18n()
</script>
<template>
 <div class="stack"><p>{{ execution.trigger_id }} · {{ execution.status }}</p><p class="muted">{{ execution.created_at }}</p>
 <ol class="m-0 list-none space-y-4 p-0"><li v-for="(r, i) in execution.results" :key="i" class="card stack">
 <h3 class="m-0"><RouterLink v-if="r.action_id" :to="{ name: 'action-editor', params: { tenant: tenantName, id: r.action_id } }">{{ r.action_name }}</RouterLink><span v-else>{{ r.action_name }}</span></h3><p class="m-0 text-sm text-muted">{{ t('monitor.timing', { start: r.started_at, end: r.ended_at }) }}</p>
 <p v-if="r.job_id">{{ t('actions.jobAttempt', { id: r.job_id, attempt: r.job_attempt }) }}</p>
 <p v-if="r.denial_reason" class="text-warning">{{ t('monitor.denialReason', { reason: r.denial_reason }) }}</p>
 <p v-if="r.error" role="alert" class="text-danger">{{ r.error.id }}: {{ r.error.message }}</p>
 <h4 class="m-0">{{ t('monitor.console') }}</h4><pre v-if="r.logs?.length" class="m-0 max-w-full overflow-auto whitespace-pre-wrap break-all">{{ r.logs.join('\n') }}</pre><p v-else class="m-0 text-muted">{{ t('monitor.noConsole') }}</p>
 </li></ol></div>
</template>
