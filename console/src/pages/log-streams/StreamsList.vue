<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { LogStream, StreamStatus } from '../../api/client'
import { errorMessage } from '../../context'
import { unavailable, useMonitoringContext } from '../logs/shared'
import { cloudStream } from './schema'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
const { t } = useI18n(), { api, tenant, key, capture, current } = useMonitoringContext()
const health = ref<StreamStatus[]>([]), healthError = ref(''), healthMissing = ref(false)
const items = ref<LogStream[]>([]), error = ref(''), missing = ref(false), busy = ref(false), deleting = ref<LogStream>(), confirm = ref(false)
let generation = 0
const delivery = (id: string) => health.value.find(s => s.id === id)
async function loadHealth(c: ReturnType<typeof capture>, gen: number) {
 if(!c) return
 try { const r = await api.logStreamStatus(c.tenant); if(current(c) && gen === generation) { health.value = r; healthError.value = ''; healthMissing.value = false } }
 catch(e) { if(current(c) && gen === generation) { healthMissing.value = unavailable(e); healthError.value = healthMissing.value ? '' : errorMessage(e) } }
}
async function load() {
 const c = capture(), gen = ++generation; items.value = []; health.value = []; healthError.value = ''; healthMissing.value = false; error.value = ''; missing.value = false; busy.value = false; confirm.value = false; deleting.value = undefined
 if(!c) return
 busy.value = true
 try { await Promise.all([loadHealth(c, gen), (async () => { const r = await api.listLogStreams(c.tenant); if(current(c) && gen === generation) items.value = r })()]) }
 catch(e) { if(current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && gen === generation) busy.value = false }
}
async function status(s: LogStream) {
 const c = capture(), gen = generation; if(!c || busy.value) return
 busy.value = true; error.value = ''
 try { const r = await api.updateLogStream(c.tenant, s.id, { status: s.status === 'active' ? 'paused' : 'active' }); if(current(c) && gen === generation) { items.value = items.value.map(v => v.id === s.id ? r : v); await loadHealth(c, gen) } }
 catch(e) { if(current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && gen === generation) busy.value = false }
}
async function remove() {
 const c = capture(), gen = generation, s = deleting.value; if(!c || !s || busy.value) return
 busy.value = true; error.value = ''
 try { await api.deleteLogStream(c.tenant, s.id); if(current(c) && gen === generation) { items.value = items.value.filter(v => v.id !== s.id); health.value = health.value.filter(v => v.id !== s.id); confirm.value = false; deleting.value = undefined } }
 catch(e) { if(current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && gen === generation) busy.value = false }
}
watch(key, load, { immediate: true })
</script>
<template><div v-if="tenant" class="stack"><div class="row"><h1>{{ t('monitor.streams') }}</h1><span class="flex-1" /><RouterLink :to="{ name: 'stream-new', params: { tenant: tenant.name } }">{{ t('monitor.createStream') }}</RouterLink></div><p class="muted">{{ t('monitor.deliveryHint') }}</p><Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="healthMissing && !missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="healthError" kind="warn">{{ t('monitor.healthFailed') }} {{ healthError }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p><div class="overflow-x-auto"><table class="data"><thead><tr><th>{{ t('monitor.name') }}</th><th>{{ t('monitor.streamType') }}</th><th>{{ t('monitor.status') }}</th><th>{{ t('monitor.delivery') }}</th><th>{{ t('monitor.controls') }}</th></tr></thead><tbody><tr v-for="s in items" :key="s.id"><td><RouterLink :to="{ name: 'stream-edit', params: { tenant: tenant.name, id: s.id } }">{{ s.name || s.id }}</RouterLink></td><td>{{ t(`monitor.sinkTypes.${s.type}`) }}</td><td>{{ t(`monitor.statuses.${s.status}`) }}</td><td><p class="m-0">{{ cloudStream(s.type) ? t('monitor.notDelivered') : t('monitor.workerDelivery') }}</p><dl v-if="delivery(s.id) && !cloudStream(s.type)" class="m-0 mt-2 grid gap-1 text-sm"><dt class="font-bold">{{ t('monitor.lastSuccess') }}</dt><dd class="m-0">{{ delivery(s.id)?.last_success_at || t('monitor.neverDelivered') }}</dd><dt class="font-bold">{{ t('monitor.nextAttempt') }}</dt><dd class="m-0">{{ delivery(s.id)?.next_at || t('monitor.notScheduled') }}</dd><dd class="m-0">{{ t('monitor.failedAttempts', { count: delivery(s.id)?.failures || 0 }) }}</dd><dd v-if="delivery(s.id)?.last_error_class" class="m-0"><span>{{ t('monitor.lastError') }}: </span><code>{{ delivery(s.id)?.last_error_class }}</code></dd></dl></td><td><div class="row flex-wrap"><Button v-if="!cloudStream(s.type)" :disabled="busy" @click="status(s)">{{ s.status === 'active' ? t('monitor.pause') : t('monitor.resume') }}</Button><Button variant="danger" :disabled="busy" @click="deleting = s; confirm = true">{{ t('monitor.delete') }}</Button></div></td></tr><tr v-if="!items.length && !busy"><td colspan="5">{{ t('monitor.noStreams') }}</td></tr></tbody></table></div><ConfirmDialog v-model:open="confirm" :title="t('monitor.deleteTitle')" :description="t('monitor.deleteHint')" :confirm-label="t('monitor.delete')" :busy="busy" :error="error" @confirm="remove" /></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner></template>
