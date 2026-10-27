<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import CodeEditor from '../CodeEditor.vue'
import { MAX_SCRIPT_BYTES, utf8Bytes } from './social'

// The bounded fetchUserProfile editor: a size counter against the server's
// limit. There is no test runner: the script needs a live provider token.
defineProps<{ id: string; label: string; readonly?: boolean; error?: string }>()
const model = defineModel<string>({ required: true })
const { t } = useI18n()
const used = computed(() => utf8Bytes(model.value))
const over = computed(() => used.value > MAX_SCRIPT_BYTES)
</script>

<template>
  <div class="stack">
    <label :for="id" class="font-bold">{{ label }}</label>
    <p :id="id + '-hint'" class="muted">{{ t('social.scriptHint') }}</p>
    <CodeEditor :id="id" v-model="model" :label="label" :readonly="readonly" />
    <p :class="over ? 'error' : 'muted'" :data-testid="id + '-size'" aria-live="polite">
      {{ over ? t('social.scriptTooLarge', { max: MAX_SCRIPT_BYTES }) : t('social.scriptSize', { used, max: MAX_SCRIPT_BYTES }) }}
    </p>
    <p v-if="error" :id="id + '-error'" class="error" role="alert">{{ error }}</p>
  </div>
</template>
