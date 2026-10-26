<script setup lang="ts">
// ProxySecret shows the one-time proxy key from a successful verify. It keeps
// the key only in its prop: never in storage, the URL or a later request.
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'

defineProps<{ secret: string }>()
const emit = defineEmits<{ done: [] }>()
const { t } = useI18n()
</script>

<template>
  <section class="mb-4 rounded border-2 border-warn-border bg-warn-soft px-4 py-3" aria-labelledby="proxy-secret-title" aria-live="assertive">
    <h2 id="proxy-secret-title" class="m-0">{{ t('customDomain.secretTitle') }}</h2>
    <p>{{ t('customDomain.secretOnce') }}</p>
    <code class="block break-all" data-secret>{{ secret }}</code>
    <div class="row mt-2">
      <CopyButton :value="secret" />
      <Button @click="emit('done')">{{ t('customDomain.secretDone') }}</Button>
    </div>
  </section>
</template>
