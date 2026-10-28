<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ActionTestResponse } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ActionNav from './ActionNav.vue'
import { eventTemplates } from './templates'
import { useActionContext } from './context'
const { t } = useI18n(), { api, tenant, key, capture, current } = useActionContext()
const template = ref('post-login')
function loadTemplate() { event.value = JSON.stringify(eventTemplates[template.value], null, 2) }
const event = ref('{}'), result = ref<ActionTestResponse['payload']>(), error = ref(''), busy = ref(false)
async function initialize() {
 const c = capture(); if(!c) return
 try {
  const action = await api.getAction(c.tenant, c.id), id = action.supported_triggers?.[0]?.id
  if(current(c) && id && eventTemplates[id] && event.value === '{}') { template.value = id; loadTemplate() }
 } catch(e) { if(current(c)) error.value = errorMessage(e) }
}
watch(key, () => { event.value = '{}'; template.value = 'post-login'; result.value = undefined; error.value = ''; busy.value = false; void initialize() }, { immediate: true })
async function run() {
  const c = capture()
  if (!c || busy.value) return
  error.value = ''; result.value = undefined
  let payload: Record<string, unknown>
  try {
    const parsed: unknown = JSON.parse(event.value)
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(t('actions.invalidEvent'))
    payload = parsed as Record<string, unknown>
  } catch { error.value = t('actions.invalidEvent'); return }
  busy.value = true
  try { const r = await api.testAction(c.tenant, c.id, { payload }); if (current(c)) result.value = r.payload }
  catch (e) { if (current(c)) error.value = errorMessage(e) }
  finally { if (current(c)) busy.value = false }
}
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><h1>{{ t('actions.test') }}</h1><p class="muted">{{ t('actions.testHint') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <Field id="event-template" :label="t('actions.template')"><select id="event-template" v-model="template" :disabled="busy"><option v-for="(_, id) in eventTemplates" :key="id" :value="id">{{ id }}</option></select></Field><Button :disabled="busy" @click="loadTemplate">{{ t('actions.loadTemplate') }}</Button>
    <form class="stack" @submit.prevent="run"><Field id="action-event" :label="t('actions.event')"><textarea id="action-event" v-model="event" rows="12" spellcheck="false" :disabled="busy" class="font-mono" /></Field><Button type="submit" variant="primary" :disabled="busy">{{ t('actions.runTest') }}</Button></form>
    <p v-if="busy" role="status">{{ t('loading') }}</p>
    <section v-if="result" class="stack" aria-live="polite">
      <Banner v-if="result.error" kind="error"><strong>{{ result.error.id }}</strong> {{ result.error.message }}</Banner>
      <div class="card"><h2>{{ t('actions.commands') }}</h2><pre class="overflow-auto whitespace-pre-wrap">{{ JSON.stringify(result.commands ?? [], null, 2) }}</pre></div>
      <div class="card"><h2>{{ t('actions.logs') }}</h2><pre class="overflow-auto whitespace-pre-wrap">{{ (result.logs ?? []).join('\n') || t('actions.noLogs') }}</pre></div>
      <p v-if="result.duration_ms !== undefined">{{ t('actions.duration', { ms: result.duration_ms }) }}</p>
      <RouterLink v-if="result.execution_id" :to="{ name: 'action-execution', params: { tenant: tenant.name }, query: { execution: result.execution_id } }">{{ t('actions.viewExecution') }}</RouterLink>
    </section>
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
