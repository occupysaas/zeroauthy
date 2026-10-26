<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { BrandingObject, BrandingPreview } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { bindPreviewStyleNonce } from './preview'
import { hostedLocales } from '../settings/hostedLocales'
const props = defineProps<{ overrides?: BrandingObject; invalid?: boolean }>()
const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()
const screen = ref('login')
const language = ref('en')
const result = ref<BrandingPreview>()
const sandboxDocument = computed(() => bindPreviewStyleNonce(result.value?.html ?? ''))
const error = ref('')
const busy = ref(false)
let generation = 0
const screens = ['login', 'login-id', 'login-password', 'signup', 'reset_request', 'reset_email_sent', 'reset_password', 'reset_success', 'reset_error', 'email_verification', 'consent', 'logout_confirm', 'logged_out', 'device_code', 'device_confirm', 'device_result', 'error']
watch([tenant, screen, language, () => props.overrides, () => props.invalid], () => { generation++; result.value = undefined; error.value = ''; busy.value = false }, { deep: true })
onBeforeUnmount(() => { generation++ })
async function render() {
  const current = tenant.value
  if (!current || busy.value || props.invalid) return
  const mine = ++generation
  busy.value = true; error.value = ''; result.value = undefined
  try {
    const preview = await api.previewTenantBranding(current, { screen: screen.value, language: language.value, ...(props.overrides ? { overrides: props.overrides } : {}) })
    if (mine === generation) result.value = preview
  } catch (e) { if (mine === generation) error.value = errorMessage(e) }
  finally { if (mine === generation) busy.value = false }
}
</script>
<template>
  <section class="grid gap-4 py-4">
    <h2>{{ t('branding.tabs.preview') }}</h2>
    <p>{{ t('branding.previewHint') }}</p>
    <div class="grid max-w-3xl gap-4 sm:grid-cols-2">
      <Field id="branding-preview-screen" :label="t('branding.screen')"><select id="branding-preview-screen" v-model="screen"><option v-for="name in screens" :key="name" :value="name">{{ t(`branding.screens.${name}`) }}</option></select></Field>
      <Field id="branding-preview-language" :label="t('branding.language')"><select id="branding-preview-language" v-model="language"><option v-for="code in hostedLocales" :key="code" :value="code">{{ code }}</option></select></Field>
    </div>
    <Banner v-if="invalid" kind="warn">{{ t('branding.invalidDraft') }}</Banner>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <Button :disabled="busy || invalid || tenant?.reserved" @click="render">{{ t('branding.renderPreview') }}</Button>
    <template v-if="result">
      <ul v-if="result.warnings.length"><li v-for="warning in result.warnings" :key="warning">{{ warning }}</li></ul>
      <iframe :title="t('branding.previewTitle')" sandbox="" :srcdoc="sandboxDocument" class="min-h-[42rem] w-full rounded border border-rule bg-white" />
    </template>
  </section>
</template>
