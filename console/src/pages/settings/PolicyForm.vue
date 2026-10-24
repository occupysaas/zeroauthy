<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Toggle from '../../ui/Toggle.vue'
import { hostedLocales } from './hostedLocales'
import { patchFor, read, type Panel, type Values } from './forms'
const props = defineProps<{ tenant: SystemTenant; panel: Panel }>()
const { t } = useI18n()
const { api } = useServices()
const hostedLocale = ref('en')
function addLocale() {
  const current = String(draft.value.enabled_locales || '').split('\n').filter(Boolean)
  if (!current.includes(hostedLocale.value)) current.push(hostedLocale.value)
  draft.value.enabled_locales = current.join('\n')
}
async function focusError() {
  await nextTick()
  document.getElementById(id(Object.keys(fieldErrors.value)[0] || ''))?.focus()
}
const draft = ref<Values>({})
const original = ref<Values>({})
const loading = ref(true)
const busy = ref(false)
const error = ref('')
const saved = ref(false)
const fieldErrors = ref<Record<string, string>>({})
let generation = 0
const patch = computed(() => patchFor(props.panel.fields, original.value, draft.value, props.panel.captcha))
const dirty = computed(() => Object.keys(patch.value).length > 0)
function fill(data: Values) {
  const values: Values = {}
  for (const f of props.panel.fields) {
    const value = read(data, f.path)
    values[f.path] = f.kind === 'password' ? '' : f.kind === 'lines' ? (Array.isArray(value) ? value.join('\n') : '') : value ?? (f.kind === 'toggle' ? false : '')
  }
  draft.value = values
  original.value = { ...values }
}
async function load() {
  const mine = ++generation
  const tenant = props.tenant
  const panel = props.panel
  loading.value = true; busy.value = false; error.value = ''; saved.value = false; fieldErrors.value = {}; draft.value = {}; original.value = {}
  try { const result = await panel.load(api, tenant); if (mine === generation) fill(result) }
  catch (e) { if (mine === generation) error.value = errorMessage(e) }
  finally { if (mine === generation) loading.value = false }
}
watch(() => [props.tenant.name, props.tenant.host, props.panel.key], load, { immediate: true })
onBeforeUnmount(() => { generation++; draft.value = {}; original.value = {} })
async function save() {
  if (busy.value || loading.value || !dirty.value) return
  const mine = generation
  const tenant = props.tenant
  const panel = props.panel
  error.value = ''; saved.value = false; fieldErrors.value = {}
  if (panel.captcha) {
    for (const f of panel.fields) {
      if (f.path.includes('.') && patch.value[f.path.split('.')[0]!] && !draft.value[f.path]) fieldErrors.value[f.path] = t('policy.completeCredentials')
    }
    if (Object.keys(fieldErrors.value).length) { await focusError(); return }
  }
  busy.value = true
  try {
    const result = await panel.save(api, tenant, patch.value)
    if (mine !== generation) return
    fill(result); saved.value = true
  } catch (e) {
    if (mine !== generation) return
    error.value = errorMessage(e)
    for (const f of panel.fields) {
      if (error.value.includes(f.path) || error.value.includes(f.path.split('.').at(-1)!)) fieldErrors.value[f.path] = error.value
    }
    busy.value = false
    await focusError()
  } finally { if (mine === generation) busy.value = false }
}
const id = (path: string) => path.replaceAll('.', '-')
</script>
<template>
  <div class="stack max-w-2xl py-4">
    <p v-if="panel.hint" class="muted">{{ t(panel.hint) }}</p>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <Banner v-if="error" kind="error">{{ error }} <Button v-if="!Object.keys(draft).length" @click="load">{{ t('retry') }}</Button></Banner>
    <form v-if="!loading && Object.keys(draft).length" class="stack" novalidate @submit.prevent="save">
      <div v-if="panel.key === 'languages'" class="grid gap-2 sm:grid-cols-[1fr_auto] sm:items-end">
        <Field id="hosted-locale" :label="t('policy.hostedLanguage')"><select id="hosted-locale" v-model="hostedLocale" :disabled="busy"><option v-for="code in hostedLocales" :key="code" :value="code">{{ code }}</option></select></Field>
        <Button :disabled="busy" @click="addLocale">{{ t('policy.addLocale') }}</Button>
      </div>
      <fieldset class="m-0 grid min-w-0 gap-4 border-0 p-0" :disabled="busy">
        <template v-for="f in panel.fields" :key="f.path">
          <div v-if="f.kind === 'toggle'" class="grid gap-1">
            <Toggle :model-value="Boolean(draft[f.path])" :label="t(f.label)" :disabled="f.readonly" @update:model-value="draft[f.path] = $event" />
            <p v-if="f.hint" class="muted m-0 text-sm">{{ t(f.hint) }}</p>
            <p v-if="fieldErrors[f.path]" role="alert">{{ fieldErrors[f.path] }}</p>
          </div>
          <Field v-else :id="id(f.path)" :label="t(f.label)" :hint="f.hint ? t(f.hint) : undefined" :error="fieldErrors[f.path]">
            <select v-if="f.options" :id="id(f.path)" v-model="draft[f.path]" :disabled="f.readonly" :aria-describedby="`${id(f.path)}-hint ${id(f.path)}-error`" :aria-invalid="!!fieldErrors[f.path]">
              <option value="" disabled>{{ t('policy.choose') }}</option>
              <option v-for="option in f.options" :key="option" :value="option">{{ option }}</option>
            </select>
            <textarea v-else-if="f.kind === 'lines'" :id="id(f.path)" v-model="draft[f.path] as string" rows="4" :aria-describedby="`${id(f.path)}-hint ${id(f.path)}-error`" :aria-invalid="!!fieldErrors[f.path]" />
            <input v-else-if="f.kind === 'number'" :id="id(f.path)" v-model.number="draft[f.path]" type="number" step="1" :min="f.min" :max="f.max" :aria-describedby="`${id(f.path)}-hint ${id(f.path)}-error`" :aria-invalid="!!fieldErrors[f.path]" />
            <input v-else :id="id(f.path)" v-model="draft[f.path]" :type="f.kind || 'text'" :readonly="f.readonly" :autocomplete="f.kind === 'password' ? 'new-password' : 'off'" :aria-describedby="`${id(f.path)}-hint ${id(f.path)}-error`" :aria-invalid="!!fieldErrors[f.path]" />
          </Field>
        </template>
      </fieldset>
      <div class="row flex-wrap"><Button type="submit" variant="primary" :disabled="busy || !dirty">{{ t('save') }}</Button><Button :disabled="busy || !dirty" @click="draft = { ...original }; error = ''; fieldErrors = {}">{{ t('cancel') }}</Button><span v-if="dirty" class="muted">{{ t('policy.dirty') }}</span></div>
      <p v-if="saved" role="status">{{ t('policy.saved') }}</p>
    </form>
  </div>
</template>
