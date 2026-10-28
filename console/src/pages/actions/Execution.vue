<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { ActionExecution } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ActionNav from './ActionNav.vue'
import { useActionContext } from './context'
const { t } = useI18n(), route = useRoute(), { api, tenant, key, capture, current } = useActionContext()
const attempt = ref<{ job_id: string; attempt: number }>()
const executionId = ref(''), result = ref<ActionExecution>(), busy = ref(false), error = ref('')
let requests = 0
async function lookup() {
  const c = capture(), id = executionId.value.trim(), seq = ++requests
  if (!c || !id) return
  busy.value = true; error.value = ''; result.value = undefined; attempt.value = undefined
  try {
    const r = await api.getActionExecution(c.tenant, id)
    if (!current(c) || seq !== requests) return
    result.value = r
    const a = await api.getActionExecutionAttempt(c.tenant, id)
    if (current(c) && seq === requests) attempt.value = a || undefined
  }
  catch (e) { if (current(c) && seq === requests) error.value = errorMessage(e) }
  finally { if (current(c) && seq === requests) busy.value = false }
}
watch(key, () => { ++requests; executionId.value = typeof route.query.execution === 'string' ? route.query.execution : ''; result.value = undefined; attempt.value = undefined; busy.value = false; error.value = ''; if (executionId.value) void lookup() }, { immediate: true })
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><h1>{{ t('actions.execution') }}</h1><p class="muted">{{ t('actions.executionHint') }}</p>
    <form class="row flex-wrap" @submit.prevent="lookup"><Field id="execution-id" :label="t('actions.executionId')"><input id="execution-id" v-model="executionId" required :disabled="busy" /></Field><Button type="submit" variant="primary" :disabled="busy || !executionId.trim()">{{ t('actions.lookup') }}</Button></form>
    <Banner v-if="error" kind="error">{{ error }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p>
    <section v-if="result" class="card stack" aria-live="polite"><h2>{{ result.id }}</h2><p v-if="attempt">{{ t('actions.jobAttempt', { id: attempt.job_id, attempt: attempt.attempt }) }}</p><p>{{ result.trigger_id }} · {{ result.status }}</p><p class="muted">{{ result.created_at }}</p><ol><li v-for="(r, i) in result.results" :key="i"><strong>{{ r.action_name }}</strong><p>{{ r.started_at }} · {{ r.ended_at }}</p><Banner v-if="r.error" kind="error">{{ r.error.id }} {{ r.error.message }}</Banner></li></ol></section>
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
