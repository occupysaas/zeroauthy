<script setup lang="ts">
import { ref } from 'vue'
import type { Client } from '../../api/client'
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'

const { t } = useI18n()

defineProps<{ client: Client }>()
const shown = ref(false)
</script>

<template>
  <div class="grid gap-1.5">
    <span class="font-bold" id="secret-label">{{ t('apps.secret') }}</span>
    <p v-if="client.token_endpoint_auth_method === 'none'" class="m-0 muted">{{ t('apps.noSecretPublic') }}</p>
    <p v-else-if="!client.client_secret" class="m-0 muted" data-testid="rotate-to-reveal">{{ t('apps.rotateToReveal') }}</p>
    <div v-else class="row">
      <code aria-labelledby="secret-label" data-testid="secret">{{ shown ? client.client_secret : '•'.repeat(24) }}</code>
      <Button variant="ghost" :aria-pressed="shown" @click="shown = !shown">{{ shown ? t('apps.hide') : t('apps.reveal') }}</Button>
      <CopyButton :value="client.client_secret" :label="t('apps.secret')" />
    </div>
  </div>
</template>
