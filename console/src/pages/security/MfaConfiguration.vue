<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { GuardianConfiguration, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import type { Configuration } from './configuration'
import { mfaUnavailable, useMfaScope } from './scope'
const props = defineProps<{ tenant: SystemTenant; config: Configuration }>()
const { t } = useI18n(), { api } = useServices()
const { key, capture, current } = useMfaScope(() => props.tenant, () => props.config.route)
const draft = ref<Record<string, string | boolean | number>>({}), error = ref(''), busy = ref(false), loading = ref(false), saved = ref(false)
const future = computed(() => props.config.route.startsWith('sms/') || props.config.route.startsWith('phone/'))
const id = (name: string) => `mfa-config-${props.config.route.replaceAll('/', '-')}-${name}`
function clearSecrets() { for (const f of props.config.fields) if (f.secret) draft.value[f.name] = '' }
async function load() {
  const c = capture(); if(!c) return
  draft.value = {}; error.value = ''; busy.value = false; saved.value = false; loading.value = true
  try {
    const data = props.config.writeOnly ? {} : await api.getGuardianConfiguration(c.tenant, props.config.route)
    if(!current(c)) return
    const values = data as Record<string, unknown>
    for(const f of props.config.fields) draft.value[f.name] = f.secret ? '' : f.kind === 'lines' ? (Array.isArray(values[f.name]) ? (values[f.name] as string[]).join('\n') : '') : (values[f.name] ?? (f.kind === 'boolean' ? false : '')) as string | boolean | number
  } catch(e) { if(current(c)) error.value = mfaUnavailable(e) ? t('mfa.unavailable') : errorMessage(e) }
  finally { if(current(c)) loading.value = false }
}
watch(key, load, { immediate: true, flush: 'sync' })
onBeforeUnmount(clearSecrets)
async function save() {
  const c = capture(); if(!c || busy.value) return
  const route = props.config.route, body: Record<string, unknown> = {}
  for(const f of props.config.fields) {
    const value = draft.value[f.name]
    if(value === '' || value === undefined) continue
    body[f.name] = f.kind === 'lines' ? String(value).split('\n').map(v => v.trim()).filter(Boolean) : f.kind === 'number' ? Number(value) : value
  }
  clearSecrets(); busy.value = true; error.value = ''; saved.value = false
  try { await api.setGuardianConfiguration(c.tenant, route, body as GuardianConfiguration); if(current(c)) saved.value = true }
  catch(e) { if(current(c)) error.value = mfaUnavailable(e) ? t('mfa.unavailable') : errorMessage(e) }
  finally { if(current(c)) busy.value = false }
}
</script>
<template>
  <form class="card stack" :data-config="config.route" @submit.prevent="save">
    <h3>{{ t(`mfa.configTitles.${config.title}`) }}</h3>
    <Banner kind="info">{{ t(future ? 'mfa.enforced' : 'mfa.notAvailable') }}</Banner>
    <p class="muted">{{ t('mfa.secretHint') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner><p v-if="saved" role="status">{{ t('mfa.saved') }}</p>
    <fieldset :disabled="busy || loading" class="stack border-0 p-0">
      <Field v-for="field in config.fields" :id="id(field.name)" :key="field.name" :label="t(`mfa.fields.${field.name}`)">
        <select v-if="field.options" :id="id(field.name)" v-model="draft[field.name]" :name="field.name"><option value="">{{ t('mfa.choose') }}</option><option v-for="option in field.options" :key="option" :value="option">{{ option }}</option></select>
        <textarea v-else-if="field.kind === 'lines'" :id="id(field.name)" :value="String(draft[field.name] ?? '')" :name="field.name" @input="draft[field.name] = ($event.target as HTMLTextAreaElement).value" />
        <input v-else :id="id(field.name)" v-model="draft[field.name]" :name="field.name" :type="field.secret ? 'password' : field.kind === 'boolean' ? 'checkbox' : field.kind === 'number' ? 'number' : 'text'" autocomplete="off" />
      </Field>
      <Button type="submit" variant="primary">{{ t('save') }}</Button>
    </fieldset>
  </form>
</template>
