<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import logInventory from '../../../../internal/logrules/inventory.json'
import type { LogItem } from '../../api/client'
import { errorMessage } from '../../context'
import { unavailable, useMonitoringContext } from './shared'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
const { t, te } = useI18n(), route = useRoute(), router = useRouter()
const { api, tenant, key, capture, current } = useMonitoringContext()
const text = (k: string) => typeof route.query[k] === 'string' ? route.query[k] as string : ''
const q = ref(''), type = ref(''), user = ref(''), client = ref(''), dateFrom = ref(''), dateTo = ref(''), failures = ref(false)
const failureTypes = new Set(logInventory.codes.filter(c => c.category.endsWith('.fail') || c.type === 'actions_execution_failed').map(c => c.type))
const page = computed(() => Math.max(0, Number(route.query.page) || 0))
const filtered = computed(() => !!['q', 'type', 'user', 'client', 'from', 'to', 'failures'].find(k => text(k)))
const items = ref<LogItem[]>([]), total = ref(0), error = ref(''), missing = ref(false), busy = ref(false), live = ref(false)
let timer: ReturnType<typeof setTimeout> | undefined, generation = 0, cursor: string | undefined
function stop() { clearTimeout(timer); timer = undefined; ++generation }
function query() {
 const quote = (s: string) => JSON.stringify(s)
 const terms = [q.value.trim(), type.value && `type:${quote(type.value)}`, user.value && `user_id:${quote(user.value)}`, client.value && `client_id:${quote(client.value)}`] .filter(Boolean) as string[]
 if (dateFrom.value || dateTo.value) terms.push(`date:[${dateFrom.value ? dateFrom.value + 'T00:00:00Z' : '*'} TO ${dateTo.value ? dateTo.value + 'T23:59:59.999999999Z' : '*'}]`)
 return terms.length === 1 ? terms[0] : terms.map(term => `(${term})`).join(' AND ')
}
async function load() {
 stop(); live.value = false; const gen = generation, c = capture(); items.value = []; cursor = undefined; total.value = 0; error.value = ''; missing.value = false; busy.value = false
 q.value = text('q'); type.value = text('type'); user.value = text('user'); client.value = text('client'); dateFrom.value = text('from'); dateTo.value = text('to'); failures.value = !!text('failures')
 if (!c) return
 busy.value = true
 const appliedQuery = query() || undefined
 try {
  if(failures.value) {
   // Failure categories are canonical inventory data, not a code prefix. The
   // bounded API has no category search field: collect its 1,000-result window.
   const matches: LogItem[] = []
   for(let offset = 0; offset < 10; offset++) {
    const r = await api.listLogs(c.tenant, { page: offset, per_page: 100, q: appliedQuery })
    if(!current(c) || gen !== generation) return
    matches.push(...r.logs.filter(l => failureTypes.has(l.type || '')))
    if(!r.logs.length || (offset + 1) * 100 >= Math.min(r.total, 1000)) break
   }
   items.value = matches.slice(page.value * 20, (page.value + 1) * 20); total.value = matches.length
  } else {
   const r = await api.listLogs(c.tenant, { page: page.value, per_page: 20, q: appliedQuery }); if (!current(c) || gen !== generation) return; items.value = r.logs; total.value = r.total
  }
 }
 catch (e) { if (current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if (current(c) && gen === generation) busy.value = false }
}
function search(nextPage = 0) {
 void router.push({ query: { ...(q.value ? { q: q.value } : {}), ...(type.value ? { type: type.value } : {}), ...(user.value ? { user: user.value } : {}), ...(client.value ? { client: client.value } : {}), ...(dateFrom.value ? { from: dateFrom.value } : {}), ...(dateTo.value ? { to: dateTo.value } : {}), ...(failures.value ? { failures: '1' } : {}), ...(nextPage ? { page: String(nextPage) } : {}) } })
}
async function poll(gen: number) {
 const c = capture(); if (!c || !live.value || gen !== generation) return
 try {
  // Start from the lowest displayed sequence. Page mode includes unsettled rows;
  // replaying from its lower boundary catches rows that settle after Live starts.
  const r = await api.tailLogs(c.tenant, cursor)
  if (!current(c) || !live.value || gen !== generation) return
  const ids = new Set(items.value.map(v => v.log_id)); items.value.push(...r.filter(v => v.log_id && !ids.has(v.log_id) && !!ids.add(v.log_id)))
  if (r.length) cursor = r.at(-1)?.log_id
  error.value = ''
 } catch (e) { if (current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e); if (missing.value) live.value = false } }
 finally { if (current(c) && live.value && gen === generation) timer = setTimeout(() => void poll(gen), 2000) }
}
watch(live, enabled => { stop(); if (enabled) { cursor = items.value.map(v => v.log_id).filter((v): v is string => !!v).sort()[0]; void poll(generation) } }, { flush: 'sync' })
watch(key, load, { immediate: true }); onBeforeUnmount(stop)
</script>
<template>
 <div v-if="tenant" class="stack">
  <h1>{{ t('monitor.logs') }}</h1>
  <form class="card stack" @submit.prevent="search()">
   <Field id="log-q" :label="t('monitor.search')" :hint="t('monitor.searchHint')"><input id="log-q" v-model="q" /></Field>
   <div class="grid gap-3 md:grid-cols-3">
    <Field id="logs-type" :label="t('monitor.type')"><input id="logs-type" v-model="type" /></Field>
    <Field id="logs-user" :label="t('monitor.user')"><input id="logs-user" v-model="user" /></Field>
    <Field id="logs-client" :label="t('monitor.application')"><input id="logs-client" v-model="client" /></Field>
    <Field id="logs-from" :label="t('monitor.from')"><input id="logs-from" v-model="dateFrom" type="date" /></Field>
    <Field id="logs-to" :label="t('monitor.to')"><input id="logs-to" v-model="dateTo" type="date" /></Field>
   </div>
   <div class="row flex-wrap"><label><input v-model="failures" type="checkbox" /> {{ t('monitor.failures') }}</label><Button type="submit" variant="primary">{{ t('monitor.apply') }}</Button><RouterLink :to="{ name: 'logs', params: { tenant: tenant.name } }">{{ t('monitor.clear') }}</RouterLink></div>
  </form>
  <label class="row"><input id="logs-live" v-model="live" type="checkbox" :disabled="filtered || busy || missing || !!error" /> {{ t('monitor.live') }}</label>
  <p v-if="failures" class="muted">{{ t('monitor.failureHint') }}</p><p v-if="filtered" class="muted">{{ t('monitor.liveFilterHint') }}</p><p v-if="live" role="status" class="muted">{{ t('monitor.liveHint') }}</p>
  <Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
  <p v-if="busy" role="status">{{ t('loading') }}</p>
  <div v-else class="overflow-x-auto"><table class="data min-w-[52rem]"><thead><tr><th>{{ t('monitor.time') }}</th><th>{{ t('monitor.type') }}</th><th>{{ t('monitor.description') }}</th><th>{{ t('monitor.application') }}</th><th>{{ t('monitor.connection') }}</th><th>{{ t('monitor.user') }}</th></tr></thead><tbody>
   <tr v-for="l in items" :key="l.log_id" data-testid="log-row"><td><RouterLink :to="{ name: 'log', params: { tenant: tenant.name, id: l.log_id } }">{{ l.date }}</RouterLink></td><td><code>{{ l.type }}</code><p v-if="te('monitor.types.' + l.type)" class="m-0 text-sm text-muted">{{ t(`monitor.types.${l.type}`) }}</p></td><td>{{ l.description }}</td><td>{{ l.client_name || l.client_id }}</td><td>{{ l.connection }}</td><td>{{ l.user_name || l.user_id }}</td></tr>
   <tr v-if="!items.length"><td colspan="6">{{ t('monitor.empty') }}</td></tr>
  </tbody></table></div>
  <nav v-if="!live" class="row" :aria-label="t('navPages')"><span>{{ t('monitor.total', { total }) }}</span><span class="flex-1" /><Button :disabled="busy || page === 0" @click="search(page - 1)">{{ t('previous') }}</Button><Button :disabled="busy || (page + 1) * 20 >= Math.min(total, 1000)" @click="search(page + 1)">{{ t('next') }}</Button></nav>
 <RouterView /></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
