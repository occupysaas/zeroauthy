<script setup lang="ts">
// Register an application from a Client ID Metadata Document (Plan 41b):
// preview the document's validation and mapping, then register it.
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { CimdPreview } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'

const emit = defineEmits<{ registered: [id: string] }>()
const { t } = useI18n()
const { api } = useServices()
const tenant = useTenant()

const url = ref('')
const busy = ref(false)
const error = ref('')
const done = ref('')
const preview = ref<CimdPreview | null>(null)

async function run(kind: 'preview' | 'register') {
  const tn = tenant.value
  if (!tn || !url.value) return
  busy.value = true
  error.value = ''
  done.value = ''
  try {
    if (kind === 'preview') {
      preview.value = await api.previewCimd(tn, url.value.trim())
    } else {
      const res = await api.registerCimd(tn, url.value.trim())
      done.value = t('dcr41.registered', { id: res.client_id })
      preview.value = { client_id: res.client_id, validation: res.validation, mapped_fields: res.mapped_fields }
      emit('registered', res.client_id)
    }
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <details class="card mt-6">
    <summary class="font-bold">{{ t('dcr41.register') }}</summary>
    <form class="mt-3 grid gap-3" @submit.prevent="run('preview')">
      <Field id="cimd-url" :label="t('dcr41.url')" :hint="t('dcr41.urlHint')">
        <input id="cimd-url" v-model="url" type="url" required maxlength="200" aria-describedby="cimd-url-hint" placeholder="https://app.example.com/client.json" />
      </Field>
      <div class="row">
        <Button type="submit" :disabled="busy || !url">{{ t('dcr41.preview') }}</Button>
        <Button variant="primary" :disabled="busy || !url" @click="run('register')">{{ t('dcr41.submit') }}</Button>
      </div>
    </form>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <Banner v-if="done" kind="info">{{ done }}</Banner>
    <div v-if="preview" class="mt-3 grid gap-2" aria-live="polite">
      <Banner v-if="preview.errors?.length" kind="error">{{ t('dcr41.retrieval') }}: {{ preview.errors.join('; ') }}</Banner>
      <template v-else-if="preview.validation">
        <p :class="preview.validation.valid ? '' : 'text-danger'">{{ preview.validation.valid ? t('dcr41.valid') : t('dcr41.invalid') }}</p>
        <p v-if="preview.client_id && !done" class="muted">{{ t('dcr41.existing', { id: preview.client_id }) }}</p>
        <div v-if="preview.validation.violations.length">
          <h3 class="m-0 text-base">{{ t('dcr41.violations') }}</h3>
          <ul class="violations"><li v-for="v in preview.validation.violations" :key="v">{{ v }}</li></ul>
        </div>
        <div v-if="preview.validation.warnings.length">
          <h3 class="m-0 text-base">{{ t('dcr41.warnings') }}</h3>
          <ul class="warnings"><li v-for="w in preview.validation.warnings" :key="w">{{ w }}</li></ul>
        </div>
        <div v-if="preview.mapped_fields">
          <h3 class="m-0 text-base">{{ t('dcr41.mapped') }}</h3>
          <pre class="mapped">{{ JSON.stringify(preview.mapped_fields, null, 2) }}</pre>
        </div>
      </template>
    </div>
  </details>
</template>
