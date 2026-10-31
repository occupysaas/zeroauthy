<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import type { components } from '../../api/schema'
import type { LogStream, LogStreamCreate, LogStreamPatch } from '../../api/client'
import { errorMessage } from '../../context'
import { unavailable, useMonitoringContext } from '../logs/shared'
import { categories, cloudStream, piiFields, sinks } from './schema'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
const { t } = useI18n(), router = useRouter(), { api, tenant, id, key, capture, current } = useMonitoringContext()
const type = ref<LogStream['type']>('http'), name = ref(''), values = ref<Record<string, string | boolean>>({}), priority = ref(false), filters = ref<components['schemas']['LogStreamFilter']['name'][]>([]), pii = ref<components['schemas']['LogStreamPII']['log_fields']>([]), method = ref<'mask' | 'hash'>('mask'), start = ref('')
const busy = ref(false), loaded = ref(false), error = ref(''), missing = ref(false), saved = ref(false)
const schema = computed(() => sinks.find(s => s.type === type.value)!)
let generation = 0
function clearSecrets() { schema.value.fields.filter(f => f.secret).forEach(f => { values.value[f.name] = '' }) }
function defaults() { values.value = {}; schema.value.fields.forEach(f => { values.value[f.name] = f.type === 'boolean' ? true : '' }) }
watch(type, defaults, { flush: 'sync' })
async function load() {
 const c = capture(), gen = ++generation; type.value = 'http'; name.value = ''; defaults(); priority.value = false; filters.value = []; pii.value = []; method.value = 'mask'; start.value = ''; error.value = ''; missing.value = false; saved.value = false; busy.value = false; loaded.value = false
 if(!c) return
 if(!c.id) { loaded.value = true; return }
 busy.value = true
 try {
  const r = await api.getLogStream(c.tenant, c.id); if(!current(c) || gen !== generation) return
  type.value = r.type; defaults(); name.value = r.name || ''; priority.value = !!r.isPriority; filters.value = r.filters?.map(f => f.name) || []; pii.value = r.pii_config?.log_fields || []; method.value = r.pii_config?.method || 'mask'
  for(const f of schema.value.fields) { const v = (r.sink as Record<string, unknown>)[f.name]; if(!f.secret && (typeof v === 'string' || typeof v === 'boolean')) values.value[f.name] = v }
  clearSecrets(); loaded.value = true
 } catch(e) { if(current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && gen === generation) busy.value = false }
}
async function save() {
 const c = capture(), gen = generation; if(!c || !loaded.value || busy.value) return
 error.value = ''; saved.value = false
 try {
  const sink: Record<string, unknown> = {}
  for(const f of schema.value.fields) {
   const v = values.value[f.name]
   if(v === '' || v === undefined) { if(f.required && !(c.id && f.secret)) throw new Error(t('monitor.requiredField', { field: t(`monitor.fields.${f.name}`) })); continue }
   if(f.secret && v === '[REDACTED]') throw new Error(t('monitor.markerInput'))
   if(f.type === 'array') {
    let headers: unknown
    try { headers = JSON.parse(String(v)) } catch { throw new Error(t('monitor.headersInvalid')) }
    if(!Array.isArray(headers) || !headers.every(h => h && typeof h === 'object' && typeof h.header === 'string' && typeof h.value === 'string')) throw new Error(t('monitor.headersInvalid'))
    sink[f.name] = headers
   } else sink[f.name] = v
  }
  if(start.value && !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(start.value)) throw new Error(t('monitor.startInvalid'))
  const body: LogStreamPatch = { name: name.value, isPriority: priority.value, filters: filters.value.map(name => ({ type: 'category', name })), pii_config: { log_fields: pii.value, method: method.value, algorithm: 'xxhash' }, sink }
  busy.value = true
  if(c.id) await api.updateLogStream(c.tenant, c.id, body)
  else await api.createLogStream(c.tenant, { ...body, type: type.value, sink, ...(start.value ? { startFrom: start.value } : {}) } as LogStreamCreate)
  if(!current(c) || gen !== generation) return
  clearSecrets(); saved.value = true
  await router.push({ name: 'log-streams', params: { tenant: c.tenant.name } })
 } catch(e) { if(current(c) && gen === generation) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c) && gen === generation) busy.value = false }
}
watch(key, load, { immediate: true })
</script>
<template><div v-if="tenant" class="stack"><RouterLink :to="{ name: 'log-streams', params: { tenant: tenant.name } }">{{ t('monitor.backStreams') }}</RouterLink><h1>{{ id ? t('monitor.editStream') : t('monitor.createStream') }}</h1><Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p><p v-if="saved" role="status">{{ t('monitor.saved') }}</p>
 <form v-if="loaded" class="stack" @submit.prevent="save"><fieldset :disabled="busy" class="card stack"><Field id="stream-name" :label="t('monitor.name')"><input id="stream-name" v-model="name" /></Field><Field id="stream-type" :label="t('monitor.streamType')"><select id="stream-type" v-model="type" :disabled="!!id"><option v-for="s in sinks" :key="s.type" :value="s.type">{{ t(`monitor.sinkTypes.${s.type}`) }}</option></select></Field><Banner v-if="cloudStream(type)" kind="warn">{{ t('monitor.cloudHint') }}</Banner><p class="muted">{{ t('monitor.secretHint') }}</p>
 <Field v-for="f in schema.fields" :id="f.name" :key="f.name" :label="t(`monitor.fields.${f.name}`)" :hint="f.secret ? t(id ? 'monitor.keepSecret' : 'monitor.newSecret') : undefined">
 <textarea v-if="f.type === 'array'" :id="f.name" :value="String(values[f.name] ?? '')" autocomplete="off" @input="values[f.name] = ($event.target as HTMLTextAreaElement).value" :aria-describedby="f.secret ? f.name + '-hint' : undefined" />
 <select v-else-if="f.values" :id="f.name" v-model="values[f.name]"><option value="">{{ t('monitor.choose') }}</option><option v-for="v in f.values" :key="v" :value="v">{{ v }}</option></select>
 <input v-else-if="f.type === 'boolean'" :id="f.name" v-model="values[f.name]" type="checkbox" />
 <input v-else :id="f.name" v-model="values[f.name]" :type="f.secret ? 'password' : 'text'" :autocomplete="f.secret ? 'new-password' : 'off'" :aria-describedby="f.secret ? f.name + '-hint' : undefined" />
 </Field><p v-if="type === 'http'" class="muted">{{ t('monitor.headersHint') }}</p><label><input v-model="priority" type="checkbox" /> {{ t('monitor.priority') }}</label>
 <Field v-if="!id" id="stream-start" :label="t('monitor.startFrom')" :hint="t('monitor.startHint')"><input id="stream-start" v-model="start" :placeholder="t('monitor.startPlaceholder')" aria-describedby="stream-start-hint" /></Field>
 </fieldset><fieldset :disabled="busy" class="card stack"><legend>{{ t('monitor.filters') }}</legend><p class="muted">{{ t('monitor.filtersHint') }}</p><div class="grid gap-2 md:grid-cols-2"><label v-for="cat in categories" :key="cat"><input :id="'stream-filter-' + cat.replaceAll('.', '-')" v-model="filters" type="checkbox" :value="cat" /> {{ t(`monitor.categories.${cat.replaceAll('.', '_')}`) }}</label></div></fieldset>
 <fieldset :disabled="busy" class="card stack"><legend>{{ t('monitor.pii') }}</legend><p class="muted">{{ t('monitor.piiHint') }}</p><div class="row flex-wrap"><label v-for="f in piiFields" :key="f"><input :id="'pii-' + f" v-model="pii" type="checkbox" :value="f" /> {{ t(`monitor.piiFields.${f}`) }}</label></div><Field id="pii-method" :label="t('monitor.piiMethod')"><select id="pii-method" v-model="method"><option value="mask">{{ t('monitor.mask') }}</option><option value="hash">{{ t('monitor.hash') }}</option></select></Field></fieldset><Button type="submit" variant="primary" :disabled="busy">{{ t('monitor.save') }}</Button></form></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner></template>
