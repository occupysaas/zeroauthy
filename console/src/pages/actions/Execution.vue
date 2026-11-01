<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { SystemExecution } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ActionNav from './ActionNav.vue'
import ExecutionResults from './ExecutionResults.vue'
import { unavailable } from '../logs/shared'
import { useActionContext } from './context'
const { t } = useI18n(), route = useRoute(), { api, tenant, key, capture, current } = useActionContext()
const missing = ref(false)
const attempt = ref<{ job_id: string; attempt: number }>()
const executionId = ref(''), result = ref<SystemExecution>(), busy = ref(false), error = ref('')
let requests = 0
async function lookup() {
  const c = capture(), id = executionId.value.trim(), seq = ++requests
  if (!c || !id) return
  busy.value = true; error.value = ''; missing.value = false; result.value = undefined; attempt.value = undefined
  try {
    const r = await api.getExecution(c.tenant, id)
    if (!current(c) || seq !== requests) return
    result.value = r
    // The attempt is optional metadata: a failed lookup leaves the loaded execution as it is.
    const a = await api.getActionExecutionAttempt(c.tenant, id).catch(() => undefined)
    if (current(c) && seq === requests) attempt.value = a || undefined
  }
  catch (e) { if (current(c) && seq === requests) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
  finally { if (current(c) && seq === requests) busy.value = false }
}
watch(key, () => { ++requests; executionId.value = typeof route.query.execution === 'string' ? route.query.execution : ''; result.value = undefined; attempt.value = undefined; missing.value = false; busy.value = false; error.value = ''; if (executionId.value) void lookup() }, { immediate: true })
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><h1>{{ t('actions.execution') }}</h1><p class="muted">{{ t('actions.executionHint') }}</p>
    <form class="row flex-wrap" @submit.prevent="lookup"><Field id="execution-id" :label="t('actions.executionId')"><input id="execution-id" v-model="executionId" required :disabled="busy" /></Field><Button type="submit" variant="primary" :disabled="busy || !executionId.trim()">{{ t('actions.lookup') }}</Button></form>
    <Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p>
    <section v-if="result" class="card stack" aria-live="polite"><h2>{{ result.id }}</h2><p v-if="attempt">{{ t('actions.jobAttempt', { id: attempt.job_id, attempt: attempt.attempt }) }}</p><ExecutionResults :execution="result" :tenant-name="tenant.name" /></section>
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
