<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { useMfaScope } from '../security/scope'
import { asRecord, optionsOf } from './options'
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { t } = useI18n(), { api } = useServices()
const { key, capture, current } = useMfaScope(() => props.tenant, () => props.connection.id)
const enabled = ref(false), ui = ref('both'), progressive = ref(true), local = ref(true)
const unmet = ref<string[]>([]), loading = ref(true), busy = ref(false), error = ref(''), notice = ref('')
const prerequisites = ['universal_login', 'identifier_first', 'username_or_flexible', 'custom_db_import', 'password_enabled'] as const
function reset() {
  const options = optionsOf(props.connection), methods = asRecord(options.authentication_methods), passkey = asRecord(methods.passkey), settings = asRecord(options.passkey_options)
  enabled.value = passkey.enabled === true
  ui.value = typeof settings.challenge_ui === 'string' ? settings.challenge_ui : 'both'
  progressive.value = settings.progressive_enrollment_enabled !== false
  local.value = settings.local_enrollment_enabled !== false
}
watch(() => props.connection, reset, { immediate: true })
async function load() {
  const c = capture(); reset(); busy.value = false; loading.value = true; unmet.value = []; error.value = ''; notice.value = ''
  if (!c) return
  try { const result = await api.getPasskeyPrerequisites(c.tenant, c.id); if (current(c)) unmet.value = result.unmet }
  catch (e) { if (current(c)) error.value = errorMessage(e) }
  finally { if (current(c)) loading.value = false }
}
watch([key, () => props.connection], load, { immediate: true, flush: 'sync' })
function link(name: string) {
  if (name === 'universal_login' || name === 'identifier_first') return { name: 'branding', params: { tenant: props.tenant.name }, query: { tab: 'prompts' } }
  return { name: 'connection', params: { tenant: props.tenant.name, id: props.connection.id }, query: { tab: name === 'password_enabled' ? 'password' : name === 'custom_db_import' ? 'customdb' : 'settings' } }
}
async function save() {
  const c = capture(); if (!c || busy.value || loading.value || error.value || (enabled.value && unmet.value.length)) return
  const options = optionsOf(props.connection), methods = asRecord(options.authentication_methods)
  const body = { options: { ...options, authentication_methods: { ...methods, passkey: { ...asRecord(methods.passkey), enabled: enabled.value } }, passkey_options: { ...asRecord(options.passkey_options), challenge_ui: ui.value, progressive_enrollment_enabled: progressive.value, local_enrollment_enabled: local.value } } }
  busy.value = true; notice.value = ''; error.value = ''
  try { const result = await api.updateConnection(c.tenant, c.id, body); if (current(c)) { notice.value = t('saved'); emit('saved', result) } }
  catch (e) { if (current(c)) error.value = errorMessage(e) }
  finally { if (current(c)) busy.value = false }
}
</script>
<template>
  <form id="passkey-settings" class="card stack" @submit.prevent="save">
    <h2>{{ t('passkeys.title') }}</h2>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <fieldset class="stack border-0 p-0" :disabled="busy || loading">
      <label><input id="passkey-enabled" v-model="enabled" type="checkbox" :disabled="!!error || unmet.length > 0 && !enabled" /> {{ t('passkeys.enabled') }}</label>
      <Field id="passkey-ui" :label="t('passkeys.challengeUI')"><select id="passkey-ui" v-model="ui"><option v-for="choice in ['both', 'autofill', 'button']" :key="choice" :value="choice">{{ t(`passkeys.${choice}`) }}</option></select></Field>
      <label><input id="passkey-progressive" v-model="progressive" type="checkbox" /> {{ t('passkeys.progressive') }}</label>
      <label><input id="passkey-local" v-model="local" type="checkbox" /> {{ t('passkeys.local') }}</label>
      <h3>{{ t('passkeys.prerequisites') }}</h3>
      <ul class="stack"><li v-for="item in prerequisites" :key="item" :data-prerequisite="item"><span>{{ t(unmet.includes(item) ? 'passkeys.unmet' : 'passkeys.met') }}</span> · <RouterLink :to="link(item)">{{ t(`passkeys.prerequisite.${item}`) }}</RouterLink></li></ul>
      <Button type="submit" variant="primary" :disabled="!!error || enabled && unmet.length > 0">{{ t('save') }}</Button>
    </fieldset>
    <p role="status">{{ notice }}</p>
  </form>
</template>
