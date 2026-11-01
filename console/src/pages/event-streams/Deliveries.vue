<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type EventDelivery, type EventRedelivery, type EventType } from '../../api/client'
import { errorMessage } from '../../context'
import { eventTypes, unavailable, useEventContext, validDate } from './shared'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import Attempts from './Attempts.vue'
const { t } = useI18n(), { api, tenant, id, key, capture, current } = useEventContext()
const items = ref<EventDelivery[]>([]), detail = ref<EventDelivery>(), fromDate = ref(''), toDate = ref(''), filterType = ref<EventType | ''>(''), failedOnly = ref(false), applied = ref<EventRedelivery>({})
const next = ref<string>(), cursors = ref<(string | undefined)[]>([undefined]), page = ref(0), busy = ref(false), missing = ref(false), error = ref(''), notice = ref(''), confirm = ref(false), queued = ref<string[]>([])
let sequence = 0, reads = 0
function fail(e: unknown) { missing.value = unavailable(e); error.value = missing.value ? '' : e instanceof ApiError && e.status === 409 ? t('events.conflict') : errorMessage(e) }
async function load() {
 const c = capture(), seq = sequence, read = ++reads; if(!c) return
 busy.value = true; error.value = ''; missing.value = false
 const f = applied.value
 try { const r = await api.listEventDeliveries(c.tenant, c.id, { take: 50, from: cursors.value[page.value], date_from: f.date_from, date_to: f.date_to, statuses: f.statuses?.join(','), event_types: f.event_types?.join(',') }); if(current(c) && seq === sequence && read === reads) { items.value = r.deliveries; next.value = r.next; queued.value = []; notice.value = '' } }
 catch(e) { if(current(c) && seq === sequence && read === reads) fail(e) }
 finally { if(current(c) && seq === sequence && read === reads) busy.value = false }
}
watch(key, () => { ++sequence; ++reads; items.value = []; detail.value = undefined; fromDate.value = ''; toDate.value = ''; filterType.value = ''; failedOnly.value = false; applied.value = {}; page.value = 0; cursors.value = [undefined]; next.value = undefined; busy.value = false; missing.value = false; error.value = ''; notice.value = ''; confirm.value = false; queued.value = []; void load() }, { immediate: true })
function applyFilters() {
 if(busy.value) return
 if(!validDate(fromDate.value) || !validDate(toDate.value) || fromDate.value && toDate.value && fromDate.value >= toDate.value) { error.value = t('events.dateInvalid'); return }
 applied.value = { ...(fromDate.value ? { date_from: fromDate.value } : {}), ...(toDate.value ? { date_to: toDate.value } : {}), ...(filterType.value ? { event_types: [filterType.value] } : {}), ...(failedOnly.value ? { statuses: ['failed' as const] } : {}) }
 ++sequence; items.value = []; detail.value = undefined; page.value = 0; cursors.value = [undefined]; next.value = undefined; notice.value = ''; void load()
}
function goto(forward: boolean) { if(busy.value) return; if(forward && next.value) cursors.value[++page.value] = next.value; else if(!forward && page.value) --page.value; else return; detail.value = undefined; void load() }
async function inspect(event: string) {
 const c = capture(), seq = sequence; if(!c || busy.value) return
 busy.value = true; error.value = ''; detail.value = undefined
 try { const r = await api.getEventDelivery(c.tenant, c.id, event); if(current(c) && seq === sequence) detail.value = r }
 catch(e) { if(current(c) && seq === sequence) fail(e) }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
async function redeliver(event?: string) {
 const c = capture(), seq = sequence, filters = { ...applied.value }; if(!c || busy.value) return
 busy.value = true; error.value = ''; notice.value = ''
 try {
  if(event) await api.redeliverEvent(c.tenant, c.id, event)
  else await api.redeliverEvents(c.tenant, c.id, filters)
  if(current(c) && seq === sequence) { confirm.value = false; if(event) queued.value = [...queued.value, event]; notice.value = t(event ? 'events.queuedOne' : 'events.queuedAll') }
 } catch(e) { if(current(c) && seq === sequence) fail(e) }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
</script>
<template>
 <div v-if="tenant" class="stack"><RouterLink :to="{ name: 'event-stream-edit', params: { tenant: tenant.name, id } }">{{ t('events.backStream') }}</RouterLink><h1>{{ t('events.deliveries') }}</h1><p>{{ t('events.deliveryHint') }}</p><Banner v-if="missing" kind="warn">{{ t('events.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><Banner v-if="notice">{{ notice }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p>
 <form data-testid="delivery-filters" class="card stack" @submit.prevent="applyFilters"><fieldset :disabled="busy" class="stack border-0 p-0"><Field id="event-date-from" :label="t('events.dateFrom')"><input id="event-date-from" v-model="fromDate" :placeholder="t('events.dateExample')" aria-describedby="event-date-hint" /></Field><Field id="event-date-to" :label="t('events.dateTo')"><input id="event-date-to" v-model="toDate" :placeholder="t('events.dateExample')" aria-describedby="event-date-hint" /></Field><p id="event-date-hint">{{ t('events.dateHint') }}</p><Field id="event-filter-type" :label="t('events.type')"><select id="event-filter-type" v-model="filterType"><option value="">{{ t('events.allTypes') }}</option><option v-for="v in eventTypes" :key="v" :value="v">{{ v }}</option></select></Field><label><input v-model="failedOnly" type="checkbox" /> {{ t('events.failedOnly') }}</label><Button type="submit">{{ t('events.apply') }}</Button></fieldset></form>
 <Button :disabled="busy || missing" @click="confirm = true">{{ t('events.redeliverAll') }}</Button>
 <div class="overflow-x-auto"><table class="data"><thead><tr><th scope="col">{{ t('events.eventID') }}</th><th scope="col">{{ t('events.type') }}</th><th scope="col">{{ t('events.status') }}</th><th scope="col">{{ t('events.attempts') }}</th><th scope="col">{{ t('events.controls') }}</th></tr></thead><tbody><tr v-for="d in items" :key="d.id"><td>{{ d.id }}</td><td>{{ d.event_type }}</td><td>{{ t(`events.statuses.${d.status}`) }}<p v-if="queued.includes(d.id)" role="status">{{ t('events.queued') }}</p></td><td>{{ d.attempts.length }}</td><td><div class="row flex-wrap"><Button :disabled="busy" @click="inspect(d.id)">{{ t('events.json') }}</Button><Button :disabled="busy || queued.includes(d.id)" @click="redeliver(d.id)">{{ t('events.redeliver') }}</Button></div></td></tr><tr v-if="!items.length && !busy && !missing"><td colspan="5">{{ t('events.noDeliveries') }}</td></tr></tbody></table></div>
 <div class="row"><Button :disabled="busy || !page" @click="goto(false)">{{ t('previous') }}</Button><Button :disabled="busy || !next" @click="goto(true)">{{ t('next') }}</Button><Button :disabled="busy" @click="load">{{ t('events.refresh') }}</Button></div>
 <section v-if="detail" class="card stack"><h2>{{ t('events.json') }} · {{ detail.id }}</h2><Attempts :attempts="detail.attempts" /><pre class="overflow-x-auto">{{ JSON.stringify(detail.event, null, 2) }}</pre></section>
 <ConfirmDialog v-model:open="confirm" :title="t('events.redeliverAll')" :description="t('events.redeliverHint')" :confirm-label="t('events.queueAll')" :busy="busy" :error="error" :danger="false" @confirm="redeliver()" />
 </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
