<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import type { Action, EventStream, EventStreamCreate, EventStreamPatch, EventTestResult, EventType } from '../../api/client'
import { errorMessage } from '../../context'
import { awsRegions, eventTypes, unavailable, useEventContext } from './shared'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Attempts from './Attempts.vue'
const { t } = useI18n(), router = useRouter(), { api, tenant, id, key, capture, current } = useEventContext()
const name = ref(''), destination = ref<'webhook' | 'action' | 'eventbridge'>('webhook'), status = ref<'enabled' | 'disabled'>('enabled'), subscriptions = ref<EventType[]>(['user.created'])
const endpoint = ref(''), method = ref<'basic' | 'bearer' | 'custom_header'>('basic'), originalMethod = ref(''), username = ref(''), header = ref(''), secret = ref(''), actionID = ref(''), account = ref(''), region = ref<typeof awsRegions[number]>('us-east-1'), partner = ref('')
const actions = ref<Action[]>([]), busy = ref(false), loaded = ref(false), error = ref(''), missing = ref(false), notice = ref(''), lookupError = ref(''), lookupBusy = ref(false)
const testType = ref<EventType>('user.created'), testData = ref(''), testResult = ref<EventTestResult>()
let sequence = 0, lookupSequence = 0
watch(destination, v => { secret.value = ''; if(v === 'eventbridge') status.value = 'disabled'; if(v === 'action') void loadActions() })
watch(method, () => { secret.value = '' })
async function loadActions() {
 const c = capture(), seq = ++lookupSequence; if(!c) return
 actions.value = []; lookupError.value = ''; lookupBusy.value = true
 try { const all = await api.allActions(c.tenant, 'event-stream'); if(current(c) && seq === lookupSequence) actions.value = all.filter(a => a.supported_triggers.some(tr => tr.id === 'event-stream')) }
 catch(e) { if(current(c) && seq === lookupSequence) lookupError.value = errorMessage(e) }
 finally { if(current(c) && seq === lookupSequence) lookupBusy.value = false }
}
function apply(r: EventStream) {
 name.value = r.name || ''; status.value = r.status || 'disabled'; subscriptions.value = r.subscriptions?.map(s => s.event_type) || []; destination.value = r.destination?.type || 'webhook'
 const d = r.destination
 if(d?.type === 'webhook') { endpoint.value = d.configuration.webhook_endpoint; const auth = d.configuration.webhook_authorization; method.value = auth.method; originalMethod.value = auth.method; username.value = auth.method === 'basic' ? auth.username : ''; header.value = auth.method === 'custom_header' ? auth.header_key : '' }
 if(d?.type === 'action') { actionID.value = d.configuration.action_id; void loadActions() }
 if(d?.type === 'eventbridge') { account.value = d.configuration.aws_account_id; region.value = d.configuration.aws_region; partner.value = d.configuration.aws_partner_event_source || ''; status.value = 'disabled' }
 secret.value = ''
}
async function load() {
 const c = capture(), seq = ++sequence; ++lookupSequence
 loaded.value = false; busy.value = false; error.value = ''; missing.value = false; notice.value = ''; lookupError.value = ''; lookupBusy.value = false; actions.value = []; testResult.value = undefined; testType.value = 'user.created'; testData.value = ''
 name.value = ''; destination.value = 'webhook'; status.value = 'enabled'; subscriptions.value = ['user.created']; endpoint.value = ''; method.value = 'basic'; originalMethod.value = ''; username.value = ''; header.value = ''; secret.value = ''; actionID.value = ''; account.value = ''; region.value = 'us-east-1'; partner.value = ''
 if(!c) return
 if(!c.id) { loaded.value = true; return }
 busy.value = true
 try { const r = await api.getEventStream(c.tenant, c.id); if(current(c) && seq === sequence) { apply(r); loaded.value = true } }
 catch(e) { if(current(c) && seq === sequence) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
watch(key, load, { immediate: true })
async function save() {
 const c = capture(), seq = sequence; if(!c || busy.value || !loaded.value) return
 error.value = ''; notice.value = ''
 try {
  if(!name.value.trim() || !subscriptions.value.length) throw new Error(t('events.required'))
  const base = { name: name.value, subscriptions: subscriptions.value.map(event_type => ({ event_type })), status: status.value }
  let body: EventStreamPatch | EventStreamCreate = base
  if(destination.value === 'webhook') {
   if(((!c.id || method.value !== originalMethod.value) && !secret.value) || secret.value === '[REDACTED]') throw new Error(t('events.credentialRequired'))
   const authorization = method.value === 'basic' ? { method: method.value, username: username.value, ...(secret.value ? { password: secret.value } : {}) } : method.value === 'bearer' ? { method: method.value, ...(secret.value ? { token: secret.value } : {}) } : { method: method.value, header_key: header.value, ...(secret.value ? { header_value: secret.value } : {}) }
   body = { ...base, destination: { type: 'webhook', configuration: { webhook_endpoint: endpoint.value, webhook_authorization: authorization } } }
  } else if(destination.value === 'action') {
   if(lookupBusy.value || !actions.value.some(a => a.id === actionID.value)) throw new Error(t('events.chooseAction'))
   body = { ...base, destination: { type: 'action', configuration: { action_id: actionID.value } } }
  } else if(!c.id) body = { ...base, status: 'disabled', destination: { type: 'eventbridge', configuration: { aws_account_id: account.value, aws_region: region.value } } }
  busy.value = true
  const r = c.id ? await api.updateEventStream(c.tenant, c.id, body as EventStreamPatch) : await api.createEventStream(c.tenant, body as EventStreamCreate)
  if(!current(c) || seq !== sequence) return
  secret.value = ''; notice.value = t('events.saved')
  if(c.id) apply(r)
  else await router.push({ name: 'event-stream-edit', params: { tenant: c.tenant.name, id: r.id } })
 } catch(e) { if(current(c) && seq === sequence) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && seq === sequence) { busy.value = false; secret.value = '' } }
}
async function sendTest() {
 const c = capture(), seq = sequence; if(!c?.id || busy.value) return
 error.value = ''; testResult.value = undefined
 try {
  let data: Record<string, unknown> | undefined
  if(testData.value.trim()) { try { data = JSON.parse(testData.value) } catch { throw new Error(t('events.dataInvalid')) }; if(!data || Array.isArray(data) || typeof data !== 'object') throw new Error(t('events.dataInvalid')) }
  busy.value = true
  const r = await api.testEventStream(c.tenant, c.id, { event_type: testType.value, ...(data ? { data } : {}) }); if(current(c) && seq === sequence) testResult.value = r
 } catch(e) { if(current(c) && seq === sequence) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && seq === sequence) busy.value = false }
}
</script>
<template>
 <div v-if="tenant" class="stack"><RouterLink :to="{ name: 'event-streams', params: { tenant: tenant.name } }">{{ t('events.back') }}</RouterLink><h1>{{ t(id ? 'events.edit' : 'events.create') }}</h1><Banner v-if="missing" kind="warn">{{ t('events.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><Banner v-if="notice">{{ notice }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p>
 <template v-if="loaded"><form data-testid="stream-form" class="stack" @submit.prevent="save"><fieldset :disabled="busy" class="card stack">
  <Field id="event-name" :label="t('events.name')"><input id="event-name" v-model="name" required maxlength="128" /></Field>
  <Field id="event-destination" :label="t('events.destination')"><select id="event-destination" v-model="destination" :disabled="!!id"><option v-for="d in ['webhook', 'action', 'eventbridge']" :key="d" :value="d">{{ t(`events.destinations.${d}`) }}</option></select></Field>
  <Field id="event-status" :label="t('events.status')"><select id="event-status" v-model="status" :disabled="destination === 'eventbridge'"><option value="enabled">{{ t('events.statuses.enabled') }}</option><option value="disabled">{{ t('events.statuses.disabled') }}</option></select></Field>
  <template v-if="destination === 'webhook'"><Field id="event-endpoint" :label="t('events.endpoint')"><input id="event-endpoint" v-model="endpoint" type="url" required /></Field><Field id="event-auth" :label="t('events.authorization')"><select id="event-auth" v-model="method"><option v-for="m in ['basic', 'bearer', 'custom_header']" :key="m" :value="m">{{ t(`events.methods.${m}`) }}</option></select></Field>
  <Field v-if="method === 'basic'" id="event-username" :label="t('events.username')"><input id="event-username" v-model="username" required autocomplete="off" /></Field><Field v-if="method === 'custom_header'" id="event-header" :label="t('events.header')"><input id="event-header" v-model="header" required /></Field>
  <Field id="event-secret" :label="t(`events.credentials.${method}`)" :hint="t('events.secretHint')"><input id="event-secret" v-model="secret" type="password" autocomplete="new-password" aria-describedby="event-secret-hint" /></Field><p>{{ t('events.methodHint') }}</p></template>
  <template v-if="destination === 'action'"><Banner v-if="lookupError" kind="error">{{ lookupError }}</Banner><p v-if="lookupBusy" role="status">{{ t('loading') }}</p><Field id="event-action" :label="t('events.action')" :hint="t('events.actionHint')"><select id="event-action" v-model="actionID" required :disabled="lookupBusy" aria-describedby="event-action-hint"><option value="">{{ t('events.chooseAction') }}</option><option v-for="a in actions" :key="a.id" :value="a.id">{{ a.name }}</option></select></Field><Button v-if="lookupError" @click="loadActions">{{ t('retry') }}</Button></template>
  <template v-if="destination === 'eventbridge'"><Banner kind="warn">{{ t('events.cloudHint') }}</Banner><Field id="event-aws-account" :label="t('events.awsAccount')"><input id="event-aws-account" v-model="account" :disabled="!!id" required pattern="[0-9]{12}" /></Field><Field id="event-aws-region" :label="t('events.awsRegion')"><select id="event-aws-region" v-model="region" :disabled="!!id"><option v-for="r in awsRegions" :key="r" :value="r">{{ r }}</option></select></Field><p v-if="partner">{{ t('events.partner') }}: {{ partner }}</p></template>
 </fieldset><fieldset :disabled="busy" class="card stack"><legend>{{ t('events.subscriptions') }}</legend><p>{{ t('events.subscriptionHint') }}</p><div class="grid gap-2 md:grid-cols-2"><label v-for="v in eventTypes" :key="v"><input v-model="subscriptions" type="checkbox" :value="v" /> {{ v }}</label></div></fieldset><Button variant="primary" type="submit" :disabled="busy">{{ t('events.save') }}</Button></form>
 <section v-if="id" class="card stack"><h2>{{ t('events.test') }}</h2><p>{{ t('events.testHint') }}</p><Field id="event-test-type" :label="t('events.type')"><select id="event-test-type" v-model="testType" :disabled="busy"><option v-for="v in eventTypes" :key="v" :value="v">{{ v }}</option></select></Field><Field id="event-test-data" :label="t('events.data')"><textarea id="event-test-data" v-model="testData" :disabled="busy" /></Field><Button :disabled="busy || destination === 'eventbridge'" @click="sendTest">{{ t('events.test') }}</Button><div v-if="testResult" data-testid="test-result" class="stack"><p role="status">{{ t(`events.statuses.${testResult.status}`) }}</p><Attempts :attempts="testResult.attempts" /><details><summary>{{ t('events.json') }}</summary><pre class="overflow-x-auto">{{ JSON.stringify(testResult.event, null, 2) }}</pre></details></div><RouterLink :to="{ name: 'event-deliveries', params: { tenant: tenant.name, id } }">{{ t('events.deliveries') }}</RouterLink></section>
 </template></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
