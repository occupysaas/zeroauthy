<script setup lang="ts">
import { ref } from 'vue'
import { ApiError, type ScriptTryResult, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import { parseJSON, pretty } from './options'

const { t } = useI18n()

// Try one script with test arguments. What comes back is shown here and
// kept nowhere: not in storage, not in a cache, and it is gone when this
// goes away. The server masks configuration values in it, and the page
// says what the mask does not cover.
const props = defineProps<{ tenant: SystemTenant; connectionId: string; script: string; dirty: boolean }>()
const { api } = useServices()

const templates: Record<string, unknown[]> = {
  login: ['user@example.com', 'a-test-password'],
  get_user: ['user@example.com'],
  create: [{ email: 'user@example.com', password: 'a-test-password' }],
  verify: ['user@example.com'],
  change_password: ['user@example.com', 'a-new-test-password'],
  delete: ['auth0|user-id'],
  change_email: ['user@example.com', 'new@example.com', true],
}

const args = ref(pretty(templates[props.script] ?? []))
const busy = ref(false)
const result = ref<ScriptTryResult | null>(null)
const failure = ref('')
const argsError = ref('')

async function run() {
  result.value = null
  failure.value = ''
  argsError.value = ''
  const parsed = parseJSON(args.value, 'array')
  if (parsed === null) {
    argsError.value = t('conns.try.argsInvalid')
    return
  }
  busy.value = true
  try {
    result.value = await api.tryScript(props.tenant, props.connectionId, props.script, parsed as unknown[])
  } catch (e) {
    if (e instanceof ApiError && e.status === 429) failure.value = e.retryAfter ? t('conns.try.rateLimitedSeconds', { seconds: e.retryAfter }) : t('conns.try.rateLimited')
    else if (e instanceof ApiError && e.errorCode === 'script_runtime_unavailable') failure.value = t('conns.try.runtimeUnavailable')
    else failure.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="stack" :data-testid="'try-' + script">
    <label :for="'try-args-' + script" class="font-bold">{{ t('conns.try.args') }}</label>
    <textarea :id="'try-args-' + script" v-model="args" rows="3" spellcheck="false" class="mono" :aria-describedby="'try-hint-' + script" />
    <p :id="'try-hint-' + script" class="muted m-0 text-sm">{{ t('conns.try.hint') }}</p>
    <p v-if="argsError" class="m-0 text-sm text-danger" role="alert">{{ argsError }}</p>
    <Banner v-if="dirty" kind="warn">{{ t('conns.try.unsaved') }}</Banner>
    <div class="row">
      <Button :disabled="busy" @click="run">{{ busy ? t('conns.try.running') : t('conns.try.run') }}</Button>
    </div>
    <Banner v-if="failure" kind="error">{{ failure }}</Banner>
    <div v-if="result" class="stack" role="status" data-testid="try-result">
      <Banner v-if="result.error && result.error.name === 'TimeoutError'" kind="error">{{ t('conns.try.timeout') }}</Banner>
      <Banner v-else-if="result.error" kind="error">
        <strong>{{ result.error.name }}</strong>: {{ result.error.message }}
      </Banner>
      <template v-else>
        <strong>{{ t('conns.try.result') }}</strong>
        <pre class="m-0 overflow-auto rounded bg-tag p-2.5 font-mono whitespace-pre-wrap">{{ pretty(result.result) }}</pre>
      </template>
      <template v-if="result.logs.length">
        <strong>{{ t('conns.try.logs') }}</strong>
        <pre class="m-0 overflow-auto rounded bg-tag p-2.5 font-mono whitespace-pre-wrap">{{ result.logs.join('\n') }}</pre>
      </template>
      <p class="muted m-0 text-sm">{{ t('conns.try.duration', { ms: result.duration_ms }) }}</p>
      <p class="muted m-0 text-sm">{{ t('conns.try.secretsNote') }}</p>
    </div>
  </div>
</template>
