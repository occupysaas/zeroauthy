<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import type { SystemExecution } from '../../api/client'
import { errorMessage } from '../../context'
import { unavailable, useMonitoringContext } from '../logs/shared'
import Banner from '../../ui/Banner.vue'
import Field from '../../ui/Field.vue'
import Button from '../../ui/Button.vue'
import ActionNav from './ActionNav.vue'
import ExecutionResults from './ExecutionResults.vue'
const { t } = useI18n(), route = useRoute(), router = useRouter(), { api, tenant, key, capture, current } = useMonitoringContext()
const trigger = ref(''), action = ref(''), items = ref<SystemExecution[]>([]), error = ref(''), missing = ref(false), busy = ref(false), live = ref(true)
let timer: ReturnType<typeof setTimeout> | undefined, generation = 0, cursor: string | undefined
function stop() { clearTimeout(timer); timer = undefined; ++generation }
async function read(gen: number, initial = false) {
 const c = capture(); if(!c || gen !== generation) return
 busy.value = true
 try {
  const r = await api.listExecutions(c.tenant, { take: 100, after: initial ? undefined : cursor, trigger: typeof route.query.trigger === 'string' ? route.query.trigger : undefined, action: typeof route.query.action === 'string' ? route.query.action : undefined })
  if(!current(c) || gen !== generation) return
  if(initial) {
   items.value = r
   // A newest-first initial page becomes an ascending keyset for live polling.
   cursor = r[0]?.id
  } else {
   const byID = new Map(items.value.map(v => [v.id, v])); r.forEach(v => byID.set(v.id, v))
   // Refresh visible executions too: a persisted execution can gain results
   // without receiving a newer creation cursor. Do not advance from this page.
   const recent = await api.listExecutions(c.tenant, { take: 100, trigger: typeof route.query.trigger === 'string' ? route.query.trigger : undefined, action: typeof route.query.action === 'string' ? route.query.action : undefined })
   if(!current(c) || gen !== generation) return
   recent.forEach(v => byID.set(v.id, v))
   if(r.length) cursor = r.at(-1)?.id
   items.value = [...byID.values()].sort((a,b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id))
  }
  error.value = ''
 } catch(e) { if(current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e); if(missing.value) live.value = false } }
 finally { if(current(c) && gen === generation) { busy.value = false; if(live.value) timer = setTimeout(() => void read(gen, !cursor), 2000) } }
}
function load() { stop(); items.value = []; cursor = undefined; error.value = ''; missing.value = false; busy.value = false; trigger.value = typeof route.query.trigger === 'string' ? route.query.trigger : ''; action.value = typeof route.query.action === 'string' ? route.query.action : ''; void read(generation, true) }
function filter() { void router.push({ query: { ...(trigger.value ? { trigger: trigger.value } : {}), ...(action.value ? { action: action.value } : {}) } }) }
watch(key, load, { immediate: true }); watch(live, enabled => { stop(); busy.value = false; if(enabled) void read(generation, !cursor) }); onBeforeUnmount(stop)
</script>
<template><div v-if="tenant" class="stack"><ActionNav /><h1>{{ t('monitor.actionsLogs') }}</h1><form class="card stack" @submit.prevent="filter"><div class="grid gap-3 md:grid-cols-2"><Field id="execution-trigger" :label="t('monitor.trigger')"><input id="execution-trigger" v-model="trigger" /></Field><Field id="execution-action" :label="t('monitor.actionID')"><input id="execution-action" v-model="action" /></Field></div><Button type="submit">{{ t('monitor.apply') }}</Button></form><label class="row"><input v-model="live" type="checkbox" :disabled="missing" /> {{ t('monitor.live') }}</label><p class="muted">{{ t('monitor.executionLiveHint') }}</p><Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner><p v-if="busy && !items.length" role="status">{{ t('loading') }}</p><p v-else-if="!items.length">{{ t('monitor.noExecutions') }}</p><article v-for="ex in items" :key="ex.id" class="card stack"><h2><RouterLink :to="{ name: 'execution-view', params: { tenant: tenant.name, id: ex.id } }">{{ ex.id }}</RouterLink></h2><ExecutionResults :execution="ex" :tenant-name="tenant.name" /></article></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner></template>
