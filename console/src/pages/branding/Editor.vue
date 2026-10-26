<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type BrandingObject } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { hostedLocales } from '../settings/hostedLocales'
import ThemeFields from './ThemeFields.vue'
import { themeFields } from './fields'

const props = defineProps<{ kind: string }>()
const emit = defineEmits<{ draft: [{ value: BrandingObject; invalid: boolean }] }>()
const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const prompt = ref('login')
const language = ref('en')
const themeId = ref('')
const draft = ref('')
const remote = ref<BrandingObject>({})
const loading = ref(true)
const failed = ref(false)
const busy = ref(false)
const error = ref('')
const status = ref('')
let generation = 0
const drafts = new Map<string, string>()
let loadedKey = ''
const resource = computed(() => {
  switch (props.kind) {
    case 'branding': return 'branding'
    case 'prompts': return 'prompts'
    case 'template': return 'branding/templates/universal-login'
    case 'theme': return 'branding/themes/' + (themeId.value ? encodeURIComponent(themeId.value) : 'default')
    case 'text': return `prompts/${encodeURIComponent(prompt.value)}/custom-text/${encodeURIComponent(language.value)}`
    default: return `prompts/${encodeURIComponent(prompt.value)}/partials`
  }
})
const key = computed(() => `${tenant.value?.host}/${resource.value}`)
const id = computed(() => 'branding-' + props.kind)
const storedOnly = computed(() => props.kind === 'prompts' || props.kind === 'theme' || props.kind === 'partials')
function textOf(value: BrandingObject) {
  if (props.kind === 'template') return String(value.template ?? '')
  const copy = { ...value }; delete copy.themeId
  return JSON.stringify(copy, null, 2)
}
async function load() {
  if (loadedKey) drafts.set(loadedKey, draft.value)
  const current = tenant.value
  const mine = ++generation
  loadedKey = key.value
  loading.value = true; failed.value = false; busy.value = false; error.value = ''; status.value = ''; remote.value = {}
  draft.value = drafts.get(loadedKey) ?? ''
  if (!current) { loading.value = false; failed.value = true; return }
  try {
    const value = await api.getBrandingResource(current, resource.value)
    if (mine !== generation) return
    remote.value = value
    if (!drafts.has(loadedKey)) draft.value = textOf(value)
  } catch (e) {
    if (mine !== generation) return
    if (e instanceof ApiError && e.status === 404 && ['theme', 'template'].includes(props.kind)) {
      if (!drafts.has(loadedKey)) draft.value = props.kind === 'template' ? '' : '{}'
    } else { error.value = errorMessage(e); failed.value = true }
  } finally { if (mine === generation) loading.value = false }
}
watch(key, () => { void load() }, { immediate: true })
onBeforeUnmount(() => { generation++ })
function body(): BrandingObject {
  if (props.kind === 'template') return { template: draft.value }
  const value: unknown = JSON.parse(draft.value)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(t('branding.objectRequired'))
  return value as BrandingObject
}
watch([draft, loading], () => {
  if (loading.value || draft.value === textOf(remote.value)) { emit('draft', { value: {}, invalid: false }); return }
  try {
    const value = body()
    let override: BrandingObject
    switch (props.kind) {
      case 'branding': case 'prompts': override = { [props.kind]: value }; break
      case 'template': override = { template: draft.value }; break
      case 'theme': override = { themes: { preview: value }, default_theme_id: 'preview' }; break
      case 'text': override = { custom_text: { [prompt.value]: { [language.value]: value } } }; break
      default: override = { partials: { [prompt.value]: value } }
    }
    emit('draft', { value: override, invalid: false })
  } catch { emit('draft', { value: {}, invalid: true }) }
})
async function change(remove = false, create = false) {
  const current = tenant.value
  if (!current || busy.value || loading.value || failed.value || current.reserved) return
  let value: BrandingObject | undefined
  try { if (!remove) value = body() } catch (e) { error.value = errorMessage(e); return }
  const mine = generation
  const path = resource.value
  busy.value = true; error.value = ''; status.value = ''
  const activeID = String(remote.value.themeId ?? themeId.value)
  let writePath = path
  let method: 'PATCH' | 'PUT' | 'POST' | 'DELETE' = ['template', 'text', 'partials'].includes(props.kind) ? 'PUT' : 'PATCH'
  if (props.kind === 'theme') {
    method = create || !activeID ? 'POST' : 'PATCH'
    writePath = method === 'POST' ? 'branding/themes' : 'branding/themes/' + encodeURIComponent(activeID)
  }
  if (remove) {
    if (props.kind === 'text' || props.kind === 'partials') value = {}
    else { method = 'DELETE'; if (props.kind === 'theme') writePath = 'branding/themes/' + encodeURIComponent(activeID) }
  }
  try {
    const saved = await api.writeBrandingResource(current, method, writePath, value)
    if (mine !== generation) return
    if (remove) { remote.value = {}; draft.value = props.kind === 'template' ? '' : '{}' }
    else {
      if (saved && typeof saved === 'object') remote.value = saved
      if (props.kind === 'theme' && saved) draft.value = textOf(saved)
    }
    status.value = t(remove ? 'branding.cleared' : 'branding.saved')
    drafts.set(loadedKey, draft.value)
  } catch (e) {
    if (mine !== generation) return
    if (!(e instanceof ApiError) || e.status >= 500 || e.status === 408) {
      // Refresh observed state once, retaining the user's draft. Never retry a write.
      let refreshed = false
      try {
        const observed = await api.getBrandingResource(current, path)
        if (mine !== generation) return
        remote.value = observed
        refreshed = true
      } catch { if (mine === generation) failed.value = true }
      if (mine === generation) error.value = t(refreshed ? 'branding.uncertain' : 'branding.uncertainFailed')
    } else error.value = errorMessage(e)
  } finally { if (mine === generation) busy.value = false }
}
const canClear = computed(() => ['template', 'text', 'partials'].includes(props.kind) || (props.kind === 'theme' && !!(remote.value.themeId || themeId.value)))
</script>

<template>
  <section class="grid max-w-3xl gap-4 py-4">
    <h2>{{ t(`branding.tabs.${kind}`) }}</h2>
    <p>{{ t(`branding.hints.${kind}`) }}</p>
    <Banner v-if="storedOnly" kind="info">{{ t(`branding.stored.${kind}`) }}</Banner>
    <div v-if="kind === 'text' || kind === 'partials'" class="grid gap-4 sm:grid-cols-2">
      <Field :id="id + '-prompt'" :label="t('branding.prompt')"><select :id="id + '-prompt'" v-model="prompt" :disabled="busy"><option v-for="name in ['login', 'login-id', 'login-password', 'signup', 'signup-id', 'signup-password', 'login-passwordless', 'passkeys', 'confirmation', 'customized-consent', ...(kind === 'text' ? ['logout', 'reset-password', 'email-verification', 'consent', 'device-flow', 'zeroauthy'] : [])]" :key="name" :value="name">{{ name }}</option></select></Field>
      <Field v-if="kind === 'text'" :id="id + '-language'" :label="t('branding.language')"><select :id="id + '-language'" v-model="language" :disabled="busy"><option v-for="code in hostedLocales" :key="code" :value="code">{{ code }}</option></select></Field>
    </div>
    <Field v-if="kind === 'theme'" :id="id + '-lookup'" :label="t('branding.themeLookup')" :hint="t('branding.themeLookupHint')"><input :id="id + '-lookup'" v-model.lazy="themeId" :disabled="busy" /></Field>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <Button v-if="failed" @click="load">{{ t('retry') }}</Button>
    <form class="grid gap-4" @submit.prevent="change()">
      <ThemeFields v-if="kind === 'theme'" v-model="draft" :disabled="loading || failed || busy || !!tenant?.reserved" />
      <Field :id="id" :label="t(kind === 'template' ? 'branding.source' : 'branding.configuration')"><textarea :id="id" v-model="draft" rows="14" spellcheck="false" :disabled="loading || failed || busy || tenant?.reserved" class="font-mono" /></Field>
      <details v-if="kind === 'theme'"><summary>{{ t('branding.themeFields') }}</summary><dl class="grid gap-2"><template v-for="field in themeFields" :key="field.path"><dt class="font-mono">{{ field.path }}</dt><dd>{{ t(`branding.fieldState.${field.state}`) }}</dd></template></dl></details>
      <div class="flex flex-wrap gap-2">
        <Button type="submit" :disabled="loading || failed || busy || tenant?.reserved">{{ t('save') }}</Button>
        <Button v-if="kind === 'theme'" :disabled="loading || failed || busy || tenant?.reserved" @click="change(false, true)">{{ t('branding.createActivate') }}</Button>
        <Button v-if="canClear" :disabled="loading || failed || busy || tenant?.reserved" @click="change(true)">{{ t(kind === 'theme' ? 'branding.deleteTheme' : 'branding.clear') }}</Button>
        <Button :disabled="loading || busy || failed" @click="draft = textOf(remote); drafts.delete(loadedKey)">{{ t('cancel') }}</Button>
      </div>
    </form>
    <p v-if="kind === 'theme'">{{ t('branding.themeLifecycle') }}</p>
    <p v-if="status" role="status">{{ status }}</p>
  </section>
</template>
