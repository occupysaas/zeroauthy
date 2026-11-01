<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { EventStream } from '../../api/client'
import { errorMessage } from '../../context'
import { unavailable, useEventContext } from './shared'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
const { t } = useI18n(), { api, tenant, key, capture, current } = useEventContext()
const items = ref<EventStream[]>([]), error = ref(''), notice = ref(''), missing = ref(false), busy = ref(false), next = ref<string>(), cursors = ref<(string | undefined)[]>([undefined]), page = ref(0)
const deleting = ref<EventStream>(), confirm = ref(false)
let sequence = 0
let deletionContext: ReturnType<typeof capture>
function askDelete(s: EventStream) { deletionContext = capture(); deleting.value = s; confirm.value = true }
async function load() {
 const c = capture(), seq = ++sequence; if(!c) return
 busy.value = true; error.value = ''; missing.value = false
 try { const r = await api.listEventStreams(c.tenant, { take: 50, from: cursors.value[page.value] }); if(current(c) && seq === sequence) { items.value = r.eventStreams || []; next.value = r.next } }
 catch(e) { if(current(c) && seq === sequence) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
watch(key, () => { ++sequence; items.value = []; next.value = undefined; page.value = 0; cursors.value = [undefined]; deleting.value = undefined; deletionContext = undefined; confirm.value = false; notice.value = ''; busy.value = false; void load() }, { immediate: true })
function goto(forward: boolean) { if(busy.value) return; if(forward && next.value) { cursors.value[++page.value] = next.value } else if(!forward && page.value) --page.value; else return; void load() }
async function status(s: EventStream) {
 const c = capture(), seq = sequence; if(!c || !s.id || busy.value || s.destination?.type === 'eventbridge') return
 busy.value = true; error.value = ''; notice.value = ''
 try { const r = await api.updateEventStream(c.tenant, s.id, { status: s.status === 'enabled' ? 'disabled' : 'enabled' }); if(current(c) && seq === sequence) { items.value = items.value.map(v => v.id === s.id ? r : v); notice.value = t('events.updated') } }
 catch(e) { if(current(c) && seq === sequence) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
async function remove() {
 const c = deletionContext, s = deleting.value, seq = sequence; if(!c || !current(c) || !s?.id || busy.value) return
 busy.value = true; error.value = ''; notice.value = ''
 try { await api.deleteEventStream(c.tenant, s.id); if(current(c) && seq === sequence) { confirm.value = false; deleting.value = undefined; notice.value = t('events.deleted'); await load() } }
 catch(e) { if(current(c) && seq === sequence) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
</script>
<template>
 <div v-if="tenant" class="stack">
  <div class="row"><h1>{{ t('events.title') }}</h1><span class="flex-1" /><RouterLink :to="{ name: 'event-stream-new', params: { tenant: tenant.name } }">{{ t('events.create') }}</RouterLink></div>
  <p class="muted">{{ t('events.listHint') }}</p><Banner v-if="missing" kind="warn">{{ t('events.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><Banner v-if="notice">{{ notice }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p>
  <div class="overflow-x-auto"><table class="data"><thead><tr><th scope="col">{{ t('events.name') }}</th><th scope="col">{{ t('events.destination') }}</th><th scope="col">{{ t('events.status') }}</th><th scope="col">{{ t('events.failures') }}</th><th scope="col">{{ t('events.controls') }}</th></tr></thead><tbody>
  <tr v-for="s in items" :key="s.id"><td><RouterLink :to="{ name: 'event-stream-edit', params: { tenant: tenant.name, id: s.id } }">{{ s.name }}</RouterLink></td><td>{{ t(`events.destinations.${s.destination?.type}`) }}<p v-if="s.destination?.type === 'eventbridge'">{{ t('events.cloudHint') }}</p></td><td>{{ t(`events.statuses.${s.status}`) }}</td><td>{{ s.total_failures ?? 0 }}</td><td><div class="row flex-wrap"><RouterLink :to="{ name: 'event-deliveries', params: { tenant: tenant.name, id: s.id } }">{{ t('events.deliveries') }}</RouterLink><Button v-if="s.destination?.type !== 'eventbridge'" :disabled="busy" @click="status(s)">{{ t(s.status === 'enabled' ? 'events.disable' : 'events.enable') }}</Button><Button variant="danger" :disabled="busy" @click="askDelete(s)">{{ t('events.delete') }}</Button></div></td></tr>
  <tr v-if="!items.length && !busy && !missing"><td colspan="5">{{ t('events.empty') }}</td></tr></tbody></table></div>
  <div class="row"><Button :disabled="busy || !page" @click="goto(false)">{{ t('previous') }}</Button><Button :disabled="busy || !next" @click="goto(true)">{{ t('next') }}</Button><Button v-if="error || missing" :disabled="busy" @click="load">{{ t('retry') }}</Button></div>
  <ConfirmDialog v-model:open="confirm" :title="t('events.deleteTitle')" :description="t('events.deleteHint')" :confirm-label="t('events.delete')" :busy="busy" :error="error" @confirm="remove" />
 </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
